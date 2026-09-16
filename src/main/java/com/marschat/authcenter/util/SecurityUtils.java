package com.marschat.authcenter.util;

import com.marschat.common.exception.NotLoginException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * 安全工具类，获取当前登录用户信息
 */
@Component
public class SecurityUtils {

    public static Long getCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth.getName() == null) {
            throw new NotLoginException();
        }
        try {
            return Long.parseLong(auth.getName());
        } catch (NumberFormatException e) {
            throw new NotLoginException("无法解析用户身份");
        }
    }

    public static String getCurrentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth.getName() == null) {
            throw new NotLoginException();
        }
        return auth.getName();
    }

    /**
     * 当前身份是否持有平台管理员权限（{@code ROLE_ADMIN}）。
     *
     * <p>authority 由 {@code UserDetailsServiceImpl} 依 DB {@code user.role} 现查注入
     * （{@code admin} / {@code superadmin} → 追加 {@code ROLE_ADMIN}），**不信任 token claim**，
     * 故不可伪造。供 {@code AppAuthzEvaluator} 判定「平台管理员天然可管任意应用」。
     *
     * @param auth 当前认证对象（可为 null）
     * @return true = 持有 {@code ROLE_ADMIN}
     */
    public static boolean hasRoleAdmin(Authentication auth) {
        if (auth == null || auth.getAuthorities() == null) {
            return false;
        }
        for (org.springframework.security.core.GrantedAuthority a : auth.getAuthorities()) {
            if ("ROLE_ADMIN".equals(a.getAuthority())) {
                return true;
            }
        }
        return false;
    }
}
