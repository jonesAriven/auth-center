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

    @Data
    public static class AssignRequest {
        private Set<String> codes;
    }
}
