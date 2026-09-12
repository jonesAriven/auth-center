package com.marschat.authcenter.controller;

import com.marschat.authcenter.service.PermissionService;
import com.marschat.common.result.Result;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 应用间内部端点（Phase 4 · P-B）：菜单上报的应用身份直连通道。
 *
 * <p>设计动机（§18.10 待拍板项 1 选 B）：上报凭据若用管理员 token 散布到各应用配置文件是
 * 安全反模式；本通道用 {@code X-Client-Secret}（存 {@code sys_app_client.client_secret}）
 * 校验应用身份，secret 为 NULL 的应用一律拒绝（未启用=不可用）。
 * 安全链路：{@code /internal/**} 独立 SecurityFilterChain 放行 JWT（见 SecurityConfig），
 * 应用身份完全由本 controller 的 secret 常量时间比对承担。
 */
@Slf4j
@RestController
@RequestMapping("/internal/clients")
@RequiredArgsConstructor
public class InternalAppClientController {

    private final PermissionService permissionService;

    /**
     * 菜单上报（全量覆盖语义，与 /admin/clients/{clientId}/menus 同落库逻辑）。
     * body: {"menusYaml": "<menu-registry.yml 原文>"}，header: X-Client-Secret。
     * 调用方：auth-core MenuRegistryReporter / cosmic Python 等应用侧上报器。
     */
    @PutMapping("/{clientId}/menus")
    public Result<Map<String, Integer>> reportMenus(@PathVariable String clientId,
                                                    @RequestHeader(value = "X-Client-Secret", required = false) String secret,
                                                    @RequestBody Map<String, String> body) {
        if (secret == null || secret.isBlank()) {
            return Result.fail(401, "缺少 X-Client-Secret");
        }
        if (!permissionService.verifyClientSecret(clientId, secret)) {
            log.warn("菜单上报凭据校验失败: {}", clientId);
            return Result.fail(403, "client secret 校验失败");
        }
        String menusYaml = body.get("menusYaml");
        if (menusYaml == null || menusYaml.isBlank()) {
            return Result.fail(400, "缺少 menusYaml");
        }
        return Result.ok(permissionService.reportMenus(clientId, menusYaml));
    }
}
