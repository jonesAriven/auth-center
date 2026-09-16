package com.marschat.authcenter.controller;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.service.PermissionService;
import com.marschat.authcenter.service.UserService;
import com.marschat.authcenter.util.SecurityUtils;
import com.marschat.common.page.PageResult;
import com.marschat.common.result.Result;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;

/**
 * 三层权限 API · Membership / 应用级 Entitlement 的 <b>path 化</b>端点。
 *
 * <h3>为什么是 path 化（核心安全设计）</h3>
 * 改造前「应用管理员」在服务端**根本不存在**：{@code /admin/**} 全是类级
 * {@code hasRole('ADMIN')}，{@code client=xxx} 只是查询过滤参数而非权限边界，
 * 于是任一平台管理员天然能操作任意应用，应用管理员又必须持有平台 {@code ROLE_ADMIN}
 * 才能进管理面 —— 越权面出自「client 是参数」。本控制器把 {@code clientId} <b>钉进 URL path</b>：
 * <ol>
 *   <li>{@code clientId} <b>只</b>从 {@code @PathVariable} 取；body/query 里若携带 {@code client}
 *       一并**忽略**（DTO 标 {@code @JsonIgnoreProperties(ignoreUnknown=true)}）；</li>
 *   <li>鉴权（{@code @appAuthz.isAppAdmin(authentication,#clientId)}）与落库
 *       （{@code ...(#userId,#clientId,...)}）用的是**同一个 {@code #clientId} 变量**，
 *       同一次方法调用，杜绝「鉴权用 client=A、落库用 client=B」的越界；</li>
 *   <li>应用 BFF 透传时把 clientId 拼进 path（而非 query）。</li>
 * </ol>
 *
 * <h3>分层与鉴权</h3>
 * <ul>
 *   <li>成员层：{@code /members} 列本系统用户 / 加人 / 移出（{@code roleIds=[]}＝移出本系统）；</li>
 *   <li>应用级授权：{@code /users/{userId}/roles} 查改本系统角色；{@code /menu-overrides}
 *       只在平台已授范围内做菜单**减法**（{@code assignUserMenuOverrides} 仅写 deny 集，
 *       <b>不新增任何权限点</b>——防应用管理员自我提权）。</li>
 * </ul>
 * 每个方法各自声明 {@code @PreAuthorize}，**不**做类级 {@code hasRole('ADMIN')}（否则应用管理员被挡）。
 *
 * <h3>🔴 登录主链路护栏</h3>
 * 本控制器只处理 {@code /admin/**}，与 {@code /auth/login}、{@code /auth/refresh}、
 * {@code /auth/mail-login} 完全隔离；应用管理员判定 fail-closed，不给登录链路引入硬依赖。
 */
@Slf4j
@RestController
@RequestMapping("/admin/clients")
@RequiredArgsConstructor
public class AdminClientMemberController {

    private final UserService userService;
    private final PermissionService permissionService;

    /**
     * 应用管理员（或平台管理员）鉴权表达式。
     * 这里的 {@code #clientId} 与各方法落库所用的 {@code clientId} 是**同一个** path 变量。
     */
    private static final String APP_ADMIN_AUTHZ = "@appAuthz.isAppAdmin(authentication,#clientId)";

    // ───────────────────────── Membership 层（成员） ─────────────────────────

    /**
     * 列本系统用户（服务端 {@code listForAdminScoped} 强制按 client 过滤，回填 {@code appRoles}）。
     */
    @GetMapping("/{clientId}/members")
    @PreAuthorize(APP_ADMIN_AUTHZ)
    public Result<PageResult<User>> listMembers(
            @PathVariable String clientId,
            @RequestParam(required = false) String realmId,
            @RequestParam(required = false) String keyword,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size) {
        return Result.ok(userService.listForAdminScoped(clientId, realmId, keyword, page, size));
    }

    /**
     * 添加/改绑本系统成员。body: {@code {"userId":123,"roleIds":[10,11]}}。
     * 落库走 {@code assignUserClientRoles}（已含审计留痕 {@code user.client_roles}）。
     */
    @PostMapping("/{clientId}/members")
    @PreAuthorize(APP_ADMIN_AUTHZ)
    public Result<Map<String, Object>> addMember(@PathVariable String clientId,
                                                 @RequestBody AddMemberRequest body) {
        if (body == null || body.getUserId() == null || body.getRoleIds() == null) {
            return Result.fail(400, "缺少 userId 或 roleIds");
        }
        try {
            int bound = permissionService.assignUserClientRoles(
                    body.getUserId(), clientId, body.getRoleIds(), SecurityUtils.getCurrentUserId());
            return Result.ok(Map.of("bound", bound));
        } catch (IllegalArgumentException e) {
            return Result.fail(400, e.getMessage());
        }
    }

    /**
     * 移出本系统（清空该用户在本应用的全部 client 级角色，统一身份保留）。
     * 等价于 {@code assignUserClientRoles(userId, clientId, Set.of(), operatorId)}，
     * 审计 action = {@code user.remove_from_app}。
     */
    @DeleteMapping("/{clientId}/members/{userId}")
    @PreAuthorize(APP_ADMIN_AUTHZ)
    public Result<Map<String, Object>> removeMember(@PathVariable String clientId,
                                                    @PathVariable long userId) {
        int bound = permissionService.assignUserClientRoles(
                userId, clientId, Set.of(), SecurityUtils.getCurrentUserId());
        return Result.ok(Map.of("bound", bound));
    }

    // ──────────────────── 应用级 Entitlement（角色 / 菜单减法） ────────────────────

    /** 查某用户在本系统的角色绑定 id 集合。 */
    @GetMapping("/{clientId}/users/{userId}/roles")
    @PreAuthorize(APP_ADMIN_AUTHZ)
    public Result<Set<Long>> userRoles(@PathVariable String clientId, @PathVariable long userId) {
        return Result.ok(permissionService.userClientRoleIds(userId, clientId));
    }

    /**
     * 绑/解本系统角色（全量覆盖）。body: {@code {"roleIds":[10,11]}}；{@code []}＝移出。
     * 只允许本 client 的角色（{@code assignUserClientRoles} 内部校验 role 归属）。
     */
    @PutMapping("/{clientId}/users/{userId}/roles")
    @PreAuthorize(APP_ADMIN_AUTHZ)
    public Result<Map<String, Object>> assignRoles(@PathVariable String clientId,
                                                   @PathVariable long userId,
                                                   @RequestBody AssignRolesRequest body) {
        if (body == null || body.getRoleIds() == null) {
            return Result.fail(400, "缺少 roleIds");
        }
        try {
            int bound = permissionService.assignUserClientRoles(
                    userId, clientId, body.getRoleIds(), SecurityUtils.getCurrentUserId());
            return Result.ok(Map.of("bound", bound));
        } catch (IllegalArgumentException e) {
            return Result.fail(400, e.getMessage());
        }
    }

    /** 查某用户在本系统的菜单覆盖排除码集合（全码，回显用）。 */
    @GetMapping("/{clientId}/users/{userId}/menu-overrides")
    @PreAuthorize(APP_ADMIN_AUTHZ)
    public Result<Set<String>> userMenuOverrides(@PathVariable String clientId,
                                                 @PathVariable long userId) {
        return Result.ok(permissionService.userMenuOverrideCodes(userId, clientId));
    }

    /**
     * 本系统菜单覆盖（**只做减法**）。body: {@code {"codes":["marschat-kbops:menu:ports"]}}。
     *
     * <p>⚠️ 应用管理员对权限点只能「在平台已授予角色的范围内做减法」——
     * {@code assignUserMenuOverrides} 仅写 {@code sys_user_menu_override(action='deny')}，
     * **不新增任何权限点**；给角色新增权限点（平台级 {@code roles/{id}/permission-codes}）
     * 仍仅平台管理员可做。
     */
    @PutMapping("/{clientId}/users/{userId}/menu-overrides")
    @PreAuthorize(APP_ADMIN_AUTHZ)
    public Result<Map<String, Object>> assignMenuOverrides(@PathVariable String clientId,
                                                           @PathVariable long userId,
                                                           @RequestBody MenuOverrideRequest body) {
        if (body == null || body.getCodes() == null) {
            return Result.fail(400, "缺少 codes");
        }
        try {
            int denied = permissionService.assignUserMenuOverrides(userId, clientId, body.getCodes());
            return Result.ok(Map.of("denied", denied));
        } catch (IllegalArgumentException e) {
            return Result.fail(400, e.getMessage());
        }
    }

    // ─────────────────────────────── 请求体 DTO ───────────────────────────────

    /** 添加成员请求。clientId 只从 path 取；body 里多余的 {@code client} 字段一律忽略。 */
    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AddMemberRequest {
        private Long userId;
        private java.util.Set<Long> roleIds;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AssignRolesRequest {
        private java.util.Set<Long> roleIds;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class MenuOverrideRequest {
        private java.util.Set<String> codes;
    }
}
