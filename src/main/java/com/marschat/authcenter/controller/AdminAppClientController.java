package com.marschat.authcenter.controller;

import com.marschat.authcenter.service.PermissionService;
import com.marschat.common.result.Result;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 应用注册/菜单上报管理端点（Phase 2 建链路，Phase 4 管理界面消费）。
 * 与 /admin/users 同一鉴权面（链 3 Bearer + @PreAuthorize ROLE_ADMIN + CORS /admin/**）。
 */
@Slf4j
@RestController
@RequestMapping("/admin/clients")
@RequiredArgsConstructor
public class AdminAppClientController {

    private final PermissionService permissionService;
    private final JdbcTemplate jdbcTemplate;

    /**
     * 菜单上报（全量覆盖语义）。body: {"menusYaml": "<menu-registry.yml 原文>"}
     * 应用侧（MenuRegistryReporter / cosmic Python）在启动或发布时调用。
     */
    @PutMapping("/{clientId}/menus")
    @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
    public Result<Map<String, Integer>> reportMenus(@PathVariable String clientId,
                                                    @RequestBody Map<String, String> body) {
        String menusYaml = body.get("menusYaml");
        if (menusYaml == null || menusYaml.isBlank()) {
            return Result.fail(400, "缺少 menusYaml");
        }
        return Result.ok(permissionService.reportMenus(clientId, menusYaml));
    }

    /** 查看应用最近一次上报的菜单树原文（运维排查用）。 */
    @GetMapping("/{clientId}/menus")
    @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
    public Result<Map<String, Object>> getMenus(@PathVariable String clientId) {
        return Result.ok(Map.of(
                "client", clientId,
                "menusYaml", String.valueOf(permissionService.menuRegistryJson(clientId))));
    }
}
