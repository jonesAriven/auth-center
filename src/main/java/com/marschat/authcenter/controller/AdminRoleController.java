package com.marschat.authcenter.controller;

import com.marschat.authcenter.service.PermissionService;
import com.marschat.common.result.Result;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;

/**
 * 授权管理端点（Phase 4 · 角色 × 权限点，菜单授权闭环的写侧）。
 * 与 /admin/users 同一鉴权面（链3 Bearer + @PreAuthorize ROLE_ADMIN + CORS /admin/**）。
 * 设计（menu-permission-management-plan §六）：角色级=sys_role_permission 定上限；
 * 用户级 override（减法）表为后续批次，本控制器只做角色级。
 */
@Slf4j
@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminRoleController {

    private final PermissionService permissionService;

    /** 角色列表（platform + client 级）。 */
    @GetMapping("/roles")
    public Result<?> listRoles() {
        return Result.ok(permissionService.listRoles());
    }

    /** 应用权限点明细（含失效条目，授权界面树渲染）。 */
    @GetMapping("/permissions")
    public Result<?> listPermissions(@RequestParam String client) {
        return Result.ok(permissionService.listPermissions(client));
    }

    /** 角色已绑权限全码集合（client:type:code）。 */
    @GetMapping("/roles/{roleId}/permission-codes")
    public Result<?> rolePermissionCodes(@PathVariable long roleId) {
        return Result.ok(permissionService.rolePermissionCodes(roleId));
    }

    /** 角色授权全量覆盖。body: {"codes": ["marschat-kbops:menu:hosts", ...]} */
    @PutMapping("/roles/{roleId}/permission-codes")
    public Result<?> assignRolePermissions(@PathVariable long roleId,
                                           @RequestBody AssignRequest body) {
        if (body == null || body.getCodes() == null) {
            return Result.fail(400, "缺少 codes");
        }
        try {
            return Result.ok(Map.of("bound",
                    permissionService.assignRolePermissions(roleId, body.getCodes())));
        } catch (IllegalArgumentException e) {
            return Result.fail(400, e.getMessage());
        }
    }

    // ───────────── 应用角色创建 + 用户绑定（Phase 4 双视角·用户×系统） ─────────────

    /** 创建应用级角色（client scope）。body: {"code": "ops-engineer", "name": "运维工程师"} */
    @PostMapping("/clients/{clientId}/roles")
    public Result<?> createClientRole(@PathVariable String clientId,
                                      @RequestBody CreateRoleRequest body) {
        if (body == null || isBlank(body.getCode())) {
            return Result.fail(400, "缺少 code");
        }
        try {
            long id = permissionService.createClientRole(clientId, body.getCode().trim(),
                    isBlank(body.getName()) ? body.getCode().trim() : body.getName().trim(),
                    body.getDescription());
            return Result.ok(Map.of("roleId", id));
        } catch (IllegalArgumentException e) {
            return Result.fail(400, e.getMessage());
        }
    }

    /** 用户在某应用的角色绑定 id 集合。 */
    @GetMapping("/users/{userId}/client-roles")
    public Result<?> userClientRoleIds(@PathVariable long userId, @RequestParam String client) {
        return Result.ok(permissionService.userClientRoleIds(userId, client));
    }

    /** 用户在某应用的角色绑定全量覆盖。body: {"roleIds": [10, 11]} */
    @PutMapping("/users/{userId}/client-roles")
    public Result<?> assignUserClientRoles(@PathVariable long userId, @RequestParam String client,
                                           @RequestBody AssignRolesRequest body) {
        if (body == null || body.getRoleIds() == null) {
            return Result.fail(400, "缺少 roleIds");
        }
        try {
            return Result.ok(Map.of("bound",
                    permissionService.assignUserClientRoles(userId, client, body.getRoleIds())));
        } catch (IllegalArgumentException e) {
            return Result.fail(400, e.getMessage());
        }
    }

    // ───────────── 用户级菜单减法（R9：角色默认 + 用户 override 只减不加） ─────────────

    /** 用户在某应用的菜单覆盖排除码集合（全码）。 */
    @GetMapping("/users/{userId}/menu-overrides")
    public Result<?> userMenuOverrideCodes(@PathVariable long userId, @RequestParam String client) {
        return Result.ok(permissionService.userMenuOverrideCodes(userId, client));
    }

    /** 用户菜单覆盖全量覆盖。body: {"codes": ["marschat-kbops:menu:ports", ...]}（从角色权限中扣除）。 */
    @PutMapping("/users/{userId}/menu-overrides")
    public Result<?> assignUserMenuOverrides(@PathVariable long userId, @RequestParam String client,
                                             @RequestBody AssignRequest body) {
        if (body == null || body.getCodes() == null) {
            return Result.fail(400, "缺少 codes");
        }
        try {
            return Result.ok(Map.of("denied",
                    permissionService.assignUserMenuOverrides(userId, client, body.getCodes())));
        } catch (IllegalArgumentException e) {
            return Result.fail(400, e.getMessage());
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    @Data
    public static class AssignRequest {
        private Set<String> codes;
    }

    @Data
    public static class CreateRoleRequest {
        private String code;
        private String name;
        private String description;
    }

    @Data
    public static class AssignRolesRequest {
        private java.util.Set<Long> roleIds;
    }
}
