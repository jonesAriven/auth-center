package com.marschat.authcenter.controller;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.service.OperationLogService;
import com.marschat.authcenter.service.PermissionService;
import com.marschat.authcenter.service.UserService;
import com.marschat.authcenter.util.SecurityUtils;
import com.marschat.common.page.PageResult;
import com.marschat.common.result.Result;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.List;
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
 *   <li>成员层：{@code /members} 列本系统用户 / 加人 / 移出（{@code roleIds=[]}＝移出本系统）；
 *       {@code /member-candidates} 受限候选搜索（D-7 最小化例外）；</li>
 *   <li>应用级授权：{@code /users/{userId}/roles} 查改本系统角色；{@code /menu-overrides}
 *       只在平台已授范围内做菜单**减法**（{@code assignUserMenuOverrides} 仅写 deny 集，
 *       <b>不新增任何权限点</b>——防应用管理员自我提权）；</li>
 *   <li>{@code GET /roles} 列本应用角色（D-7）；同路径 {@code POST} 建角色仍为平台管理员专属
 *       （见 {@code AdminRoleController}）——同名不同权。</li>
 * </ul>
 * 每个方法各自声明 {@code @PreAuthorize}，**不**做类级 {@code hasRole('ADMIN')}（否则应用管理员被挡）。
 *
 * <h3>🔴 R8 自锁保护</h3>
 * 「移出 / 降级」若会使本应用**再无任何持有 {@code api:admin:write} 的用户**：
 * 应用管理员 → 409 拒绝；平台管理员 → 放行但 WARN 审计留痕
 * （action={@code user.remove_last_app_admin}）。管理员计数与 {@code isAppAdmin}
 * 同口径，判定异常一律 fail-closed（见 {@link #r8LastAdminGuard}）。
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
    private final OperationLogService operationLogService;

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
     * D-7 受限读：本应用「添加成员」动线的候选用户搜索。
     *
     * <p><b>最小化例外设计（Phase 12 D-7）</b>：应用管理员无 Identity 层读权限，
     * 但「往本应用加人」必须能按用户名/昵称找到人。本端点只回
     * {@code userId/username/nickname} 三字段（<b>禁</b> email/角色/状态等平台侧信息）、
     * 只列<b>尚未加入</b>本应用的用户、{@code keyword} 必填且 ≥2 字符、
     * {@code size} 服务端 clamp ≤20，并写审计（action={@code user.member_candidates_query}）。
     */
    @GetMapping("/{clientId}/member-candidates")
    @PreAuthorize(APP_ADMIN_AUTHZ)
    public Result<List<Map<String, Object>>> memberCandidates(
            @PathVariable String clientId,
            @RequestParam String keyword,
            @RequestParam(defaultValue = "10") int size) {
        String kw = keyword == null ? "" : keyword.trim();
        if (kw.length() < 2) {
            return Result.fail(400, "keyword 必填且至少 2 个字符");
        }
        int sz = Math.min(Math.max(size, 1), 20);
        List<Map<String, Object>> candidates = permissionService.listMemberCandidates(clientId, kw, sz);
        try {
            operationLogService.log(SecurityUtils.getCurrentUserId(), SecurityUtils.getCurrentUsername(),
                    "user.member_candidates_query", "user", null,
                    "搜索加人候选: client=" + clientId + " keyword=" + kw
                            + " size=" + sz + " 命中=" + candidates.size(), null);
        } catch (Exception e) {
            log.warn("成员候选查询审计失败: {}", e.getMessage());
        }
        return Result.ok(candidates);
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
        // R8：加人动线不会移除管理员，无需自锁判定（新增绑定只会增加管理员，不减）。
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
     *
     * <p>🔴 R8 自锁保护：若目标是本应用最后一名应用管理员 → 应用管理员被 409 拒绝；
     * 平台管理员放行但 WARN 留痕（见 {@link #r8LastAdminGuard}）。
     */
    @DeleteMapping("/{clientId}/members/{userId}")
    @PreAuthorize(APP_ADMIN_AUTHZ)
    public Result<Map<String, Object>> removeMember(@PathVariable String clientId,
                                                    @PathVariable long userId,
                                                    Authentication authentication) {
        String lockRejection = r8LastAdminGuard(clientId, userId, Set.of(), authentication);
        if (lockRejection != null) {
            return Result.fail(409, lockRejection);
        }
        int bound = permissionService.assignUserClientRoles(
                userId, clientId, Set.of(), SecurityUtils.getCurrentUserId());
        return Result.ok(Map.of("bound", bound));
    }

    // ──────────────────── 应用级 Entitlement（角色 / 菜单减法） ────────────────────

    /**
     * D-7 受限读：本应用的角色清单（仅本 client，scope='client'）。
     *
     * <p><b>同名不同权（Phase 12 D-7）</b>：同一路径 {@code /admin/clients/{clientId}/roles}——
     * {@code POST}（建应用级角色）= 平台管理员专属（见 {@code AdminRoleController}）；
     * 本 {@code GET}（列本应用角色）= 应用管理员可读。角色是应用级授权动线的必需原料，
     * 只回 id/code/name/description/status，不含权限点绑定明细。
     */
    @GetMapping("/{clientId}/roles")
    @PreAuthorize(APP_ADMIN_AUTHZ)
    public Result<List<Map<String, Object>>> clientRoles(@PathVariable String clientId) {
        return Result.ok(permissionService.listClientRoles(clientId));
    }

    /** 查某用户在本系统的角色绑定 id 集合。 */
    @GetMapping("/{clientId}/users/{userId}/roles")
    @PreAuthorize(APP_ADMIN_AUTHZ)
    public Result<Set<Long>> userRoles(@PathVariable String clientId, @PathVariable long userId) {
        return Result.ok(permissionService.userClientRoleIds(userId, clientId));
    }

    /**
     * 绑/解本系统角色（全量覆盖）。body: {@code {"roleIds":[10,11]}}；{@code []}＝移出。
     * 只允许本 client 的角色（{@code assignUserClientRoles} 内部校验 role 归属）。
     *
     * <p>🔴 R8 自锁保护：若本次变更将使目标用户失去 {@code api:admin:write}
     * 且其为本应用最后一名应用管理员 → 应用管理员被 409 拒绝；平台管理员放行但 WARN 留痕。
     */
    @PutMapping("/{clientId}/users/{userId}/roles")
    @PreAuthorize(APP_ADMIN_AUTHZ)
    public Result<Map<String, Object>> assignRoles(@PathVariable String clientId,
                                                   @PathVariable long userId,
                                                   @RequestBody AssignRolesRequest body,
                                                   Authentication authentication) {
        if (body == null || body.getRoleIds() == null) {
            return Result.fail(400, "缺少 roleIds");
        }
        String lockRejection = r8LastAdminGuard(clientId, userId, body.getRoleIds(), authentication);
        if (lockRejection != null) {
            return Result.fail(409, lockRejection);
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

    // ─────────────────────────── R8 自锁保护 ───────────────────────────

    /**
     * R8 自锁保护（Phase 12）：若本次变更将使「本应用再无任何持有 {@code api:admin:write} 的用户」——
     * <ul>
     *   <li>操作者是<b>平台管理员</b>（{@code ROLE_ADMIN}，authorities 由 DB 现查注入不可伪造）→
     *       允许，但记 WARN 级审计（action={@code user.remove_last_app_admin}）；</li>
     *   <li>操作者是<b>应用管理员</b> → 拒绝，返回提示文案（控制器转 409）。</li>
     * </ul>
     * 管理员计数与 {@code isAppAdmin} 同口径（{@code api:admin:write}）；
     * 判定链任何一环异常一律 fail-closed（视为将自锁 → 应用管理员被拒）。
     *
     * @return null = 放行；非 null = 拒绝文案（409）
     */
    private String r8LastAdminGuard(String clientId, long targetUserId,
                                    Collection<Long> newRoleIds, Authentication authentication) {
        try {
            if (!permissionService.isUserAppAdmin(targetUserId, clientId)) {
                return null; // 目标本就不是应用管理员，不存在自锁
            }
            if (permissionService.roleIdsKeepAppAdmin(clientId, newRoleIds)) {
                return null; // 变更后目标仍保有 api:admin:write
            }
            if (permissionService.countAppAdmins(clientId) > 1) {
                return null; // 还有其他应用管理员兜底
            }
            // 确认将自锁
            if (SecurityUtils.hasRoleAdmin(authentication)) {
                operationLogService.log(SecurityUtils.getCurrentUserId(), SecurityUtils.getCurrentUsername(),
                        "user.remove_last_app_admin", "user", targetUserId,
                        "平台管理员移出/降级应用 " + clientId + " 的最后一名应用管理员（R8 放行并留痕）", null);
                log.warn("R8 自锁放行（平台管理员）: operator={} client={} target={}",
                        SecurityUtils.getCurrentUsername(), clientId, targetUserId);
                return null;
            }
            return "该用户是应用 " + clientId + " 的最后一名管理员，此操作将导致应用管理功能无人可用；请联系平台管理员处理";
        } catch (Exception e) {
            log.warn("R8 判定异常（fail-closed，按将自锁处理）: client={} target={} err={}",
                    clientId, targetUserId, e.getMessage());
            if (SecurityUtils.hasRoleAdmin(authentication)) {
                return null; // 平台管理员本就放行
            }
            return "管理员自锁保护判定失败，已按最严格策略拒绝本次操作；请联系平台管理员处理";
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
