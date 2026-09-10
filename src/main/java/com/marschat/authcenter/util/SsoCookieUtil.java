package com.marschat.authcenter.util;

import com.marschat.authcenter.config.SsoCookieProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * SSO Cookie 工具类
 * <p>
 * 用于设置和删除跨域 SSO Token Cookie。
 * 当用户通过 OIDC 或独立登录认证成功后，调用此类的方法设置 Cookie，
 * 使所有 .marschat.online 子域都能共享登录状态。
 * <p>
 * 安全属性：
 * - HttpOnly: true（防止 JavaScript 读取，防 XSS）
 * - Secure: true（仅 HTTPS 传输，防中间人攻击）
 * - SameSite: Lax（允许顶级导航携带，防 CSRF）
 *
 * @see SsoCookieProperties
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SsoCookieUtil {

    private final SsoCookieProperties properties;

    /**
     * 设置 SSO Access Token Cookie
     *
     * @param response HTTP 响应
     * @param token    Access Token 值
     */
    public void setAccessTokenCookie(HttpServletResponse response, String token) {
        setCookie(response, properties.getAccessTokenName(), token, properties.getMaxAge());
        log.debug("已设置 SSO Access Token Cookie: name={}, domain={}, maxAge={}s",
                properties.getAccessTokenName(), properties.getDomain(), properties.getMaxAge());
    }

    /**
     * 设置 SSO Refresh Token Cookie
     *
     * @param response HTTP 响应
     * @param token    Refresh Token 值
     */
    public void setRefreshTokenCookie(HttpServletResponse response, String token) {
        setCookie(response, properties.getRefreshTokenName(), token, properties.getRefreshTokenMaxAge());
        log.debug("已设置 SSO Refresh Token Cookie: name={}, domain={}, maxAge={}s",
                properties.getRefreshTokenName(), properties.getDomain(), properties.getRefreshTokenMaxAge());
    }

    /**
     * 同时设置 Access Token 和 Refresh Token Cookie
     *
     * @param response      HTTP 响应
     * @param accessToken  Access Token
     * @param refreshToken Refresh Token
     */
    public void setSsoCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        setAccessTokenCookie(response, accessToken);
        setRefreshTokenCookie(response, refreshToken);
    }

    /**
     * 清除所有 SSO Cookie（登出时调用）
     *
     * @param response HTTP 响应
     */
    public void clearSsoCookies(HttpServletResponse response) {
        deleteCookie(response, properties.getAccessTokenName());
        deleteCookie(response, properties.getRefreshTokenName());
        log.info("已清除所有 SSO Cookie");
    }

    /**
     * 归一化 Cookie Domain。
     * <p>
     * RFC 6265 规定 Domain 属性不含前导点，Tomcat 10 的 Rfc6265CookieProcessor
     * 会对带前导点的域名抛 IllegalArgumentException。历史配置里写过
     * {@code .marschat.online}，这里统一去掉前导点做兜底，避免登录接口 500。
     */
    private String normalizedDomain() {
        String domain = properties.getDomain();
        if (domain == null) {
            return null;
        }
        String trimmed = domain.trim();
        while (trimmed.startsWith(".")) {
            trimmed = trimmed.substring(1);
        }
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * 设置 Cookie
     * <p>
     * 注意：任何 Cookie 写入异常都不应中断主流程（登录/刷新/登出），
     * 否则一个 Cookie 配置问题会把整个认证接口打成 500。
     *
     * @param response HTTP 响应
     * @param name     Cookie 名称
     * @param value    Cookie 值
     * @param maxAge   过期时间（秒）
     */
    private void setCookie(HttpServletResponse response, String name, String value, int maxAge) {
        try {
            Cookie cookie = new Cookie(name, value);
            String domain = normalizedDomain();
            if (domain != null) {
                cookie.setDomain(domain);
            }
            cookie.setPath(properties.getPath());
            cookie.setHttpOnly(true);  // 防 XSS：JavaScript 无法读取
            cookie.setSecure(properties.isSecure());  // 仅 HTTPS
            cookie.setAttribute("SameSite", properties.getSameSite());  // 防 CSRF
            cookie.setMaxAge(maxAge);
            response.addCookie(cookie);
        } catch (Exception e) {
            log.warn("设置 SSO Cookie 失败（不影响登录结果）: name={}, domain={}, err={}",
                    name, properties.getDomain(), e.getMessage());
        }
    }

    /**
     * 删除 Cookie（通过设置 maxAge=0 和过期时间实现）
     *
     * @param response HTTP 响应
     * @param name     Cookie 名称
     */
    private void deleteCookie(HttpServletResponse response, String name) {
        try {
            Cookie cookie = new Cookie(name, "");
            String domain = normalizedDomain();
            if (domain != null) {
                cookie.setDomain(domain);
            }
            cookie.setPath(properties.getPath());
            cookie.setMaxAge(0);  // 立即过期
            cookie.setHttpOnly(true);
            cookie.setSecure(properties.isSecure());
            response.addCookie(cookie);
        } catch (Exception e) {
            log.warn("清除 SSO Cookie 失败（不影响登出结果）: name={}, err={}", name, e.getMessage());
        }
    }
}
