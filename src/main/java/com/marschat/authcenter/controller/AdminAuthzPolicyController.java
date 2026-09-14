package com.marschat.authcenter.controller;

import com.marschat.authcenter.config.AuthzProperties;
import com.marschat.authcenter.service.AuthzPolicyService;
import com.marschat.authcenter.service.PermissionService;
import com.marschat.common.result.Result;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 授权默认策略运维端点（§31 默认最小权限重构）。
 *
 * <p>四个能力，全部走 {@code /admin/**} 同一鉴权面（链3 Bearer + {@code ROLE_ADMIN}）：
 * <ol>
 *   <li>{@code GET  /admin/authz/policy} —— 当前模式与每个应用的生效模式；</li>
 *   <li>{@code GET  /admin/authz/impact?client=xxx&mode=strict} —— 影响面预演
 *       （切 strict 后谁会失去哪些菜单，<b>只读不改数据</b>）；</li>
 *   <li>{@code POST /admin/authz/migrate?client=xxx[&force=true]} —— 立即对某应用执行收敛；</li>
 *   <li>{@code POST /admin/authz/restore-legacy?client=xxx} —— 一键回滚（全量 menu 补回）。</li>
 * </ol>
 */
@Slf4j
@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminAuthzPolicyController {

    private final PermissionService permissionService;

    private final AuthzPolicyService authzPolicyService;

    /** 当前策略：全局模式 + 灰度名单 + 每个应用的生效模式。 */
    @GetMapping("/authz/policy")
    public Result<?> policy() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", authzPolicyService.mode());
        out.put("strictClients", authzPolicyService.strictClients());
        List<Map<String, Object>> clients = new ArrayList<>();
        for (String c : permissionService.enabledClientIds()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("client", c);
            row.put("effectiveMode", authzPolicyService.isStrict(c)
                    ? AuthzProperties.MODE_STRICT : AuthzProperties.MODE_LEGACY);
            row.put("publicMenus", List.copyOf(authzPolicyService.publicMenuCodes(c)));
            clients.add(row);
        }
        out.put("clients", clients);
        return Result.ok(out);
    }

    /**
     * 影响面预演。
     *
     * @param client 应用标识（必填）
     * @param mode   {@code strict}（默认）/ {@code legacy}
     */
    @GetMapping("/authz/impact")
    public Result<?> impact(@RequestParam(name = "client") String client,
                            @RequestParam(name = "mode", defaultValue = AuthzProperties.MODE_STRICT) String mode) {
        if (client == null || client.isBlank()) {
            return Result.fail(400, "缺少 client");
        }
        return Result.ok(permissionService.impact(client.trim(), mode));
    }

    /**
     * 对某应用立即执行 strict 收敛（补发 public 菜单 + 摘除非 public 绑定）。
     *
     * @param force true = 忽略「已迁移」标记强制重跑（管理员想重新收窄时用）
     */
    @PostMapping("/authz/migrate")
    public Result<?> migrate(@RequestParam(name = "client") String client,
                             @RequestParam(name = "force", defaultValue = "false") boolean force) {
        if (client == null || client.isBlank()) {
            return Result.fail(400, "缺少 client");
        }
        String c = client.trim();
        if (!authzPolicyService.isStrict(c)) {
            return Result.fail(400, "应用 " + c + " 当前生效模式为 legacy，不执行 strict 收敛"
                    + "（如需切换：marschat.authz.mode=strict 或加入 strict-clients）");
        }
        try {
            log.info("管理员手动触发 strict 收敛: client={} force={}", c, force);
            return Result.ok(permissionService.enforceStrictForClient(c, force));
        } catch (Exception e) {
            log.warn("strict 收敛失败: {} {}", c, e.getMessage());
            return Result.fail(500, "收敛失败: " + e.getMessage());
        }
    }

    /**
     * 一键回滚（legacy 等价态）：把该应用<b>全部有效 menu</b>补回默认可见角色。
     *
     * <p>只补 menu、不补 api —— 接口=动作，任何模式下都不自动授予
     * （kbops {@code hosts:create} 的止血不受回滚影响）。
     */
    @PostMapping("/authz/restore-legacy")
    public Result<?> restoreLegacy(@RequestParam(name = "client") String client) {
        if (client == null || client.isBlank()) {
            return Result.fail(400, "缺少 client");
        }
        String c = client.trim();
        try {
            int n = authzPolicyService.grantAllMenus(c);
            log.info("管理员手动回滚默认授权: client={} 补回 {} 条", c, n);
            return Result.ok(Map.of("client", c, "restored", n));
        } catch (Exception e) {
            log.warn("默认授权回滚失败: {} {}", c, e.getMessage());
            return Result.fail(500, "回滚失败: " + e.getMessage());
        }
    }
}
