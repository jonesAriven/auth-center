package com.marschat.authcenter.security;

import com.marschat.authcenter.service.PermissionService;
import com.marschat.authcenter.util.SecurityUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * 应用管理员判定求值器（三层权限 API · Membership / 应用级 Entitlement 闸门）。
 *
 * <p>作为 Spring Bean 以固定名 {@code appAuthz} 注册，供 {@code @PreAuthorize} 的 SpEL
 * 调用（形如 {@code @appAuthz.isAppAdmin(authentication,#clientId)}）。它把「谁能管某个应用的
 * 用户与角色」这一判据**统一下沉到 auth-center**（设计规格 §1.6），应用 BFF 只做透传与收窄，
 * 避免在 6 个应用里各抄一份鉴权实现（改一处漏五处的历史教训）。
 *
 * <h3>判定口径（两段）</h3>
 * <ol>
 *   <li><b>平台管理员</b>（持 {@code ROLE_ADMIN}，含 {@code superadmin}）→ 直接 {@code true}，
 *       天然可管任意应用；</li>
 *   <li>否则 → 交 {@link PermissionService#isAppAdmin(long, String)}，判「调用者是否持有
 *       <b>该 client</b> 的 {@code api:admin:write} 权限点」（口径 A）。</li>
 * </ol>
 *
 * <h3>调用者身份来源</h3>
 * 调用者 uid 从 {@code SecurityContext} 的 principal 取 —— {@code JwtAuthenticationFilter}
 * 已把 principal 设为 {@code UserDetails}，其 {@code getUsername()} 即 user id 字符串，
 * 故 {@code auth.getName()} 即 uid（与 {@link SecurityUtils#getCurrentUserId()} 同源）。
 *
 * <h3>🔴 登录主链路护栏</h3>
 * 本类**只**在 {@code /admin/**} 的方法级鉴权（{@code @PreAuthorize}）上被求值，
 * **绝不**出现在 {@code /auth/login}、{@code /auth/refresh}、{@code /auth/mail-login} 路径上。
 * 所有判定失败一律 **fail-closed**（返回 {@code false}，拒绝），且不向登录链路引入新的
 * DB/缓存硬依赖 —— auth-center 是 SSO 枢纽，登录 500 = 全站不可用。
 */
@Slf4j
@Component("appAuthz")
@RequiredArgsConstructor
public class AppAuthzEvaluator {

    private final PermissionService permissionService;

    /**
     * 调用者是否为指定应用的「应用管理员」（或平台管理员）。
     *
     * @param auth     当前认证对象（由 {@code @PreAuthorize} 的 {@code authentication} 传入）
     * @param clientId 目标应用标识（**只**来自 URL path，服务端强制注入，见
     *                 {@code AdminClientMemberController}）
     * @return true = 允许执行该应用的管理动作
     */
    public boolean isAppAdmin(Authentication auth, String clientId) {
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }
        // ① 平台管理员（ROLE_ADMIN，含 superadmin）：天然可管任意应用
        if (SecurityUtils.hasRoleAdmin(auth)) {
            return true;
        }
        if (clientId == null || clientId.isBlank()) {
            return false;
        }
        // ② 应用管理员：持有该 client 的 api:admin:write 权限点
        long uid;
        try {
            uid = Long.parseLong(auth.getName());
        } catch (NumberFormatException e) {
            log.debug("principal 非数字 uid，视为非应用管理员: {}", auth.getName());
            return false;
        }
        try {
            return permissionService.isAppAdmin(uid, clientId);
        } catch (Exception e) {
            log.warn("应用管理员判定异常（fail-closed）: uid={} client={} err={}",
                    uid, clientId, e.getMessage());
            return false;
        }
    }
}
