package com.marschat.authcenter.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * SSO Cookie 配置属性
 * <p>
 * 用于配置跨域 SSO Token Cookie 的属性，使所有 .marschat.online 子域可以共享登录状态。
 * <p>
 * 配置前缀：sso.cookie
 *
 * @example
 * <pre>
 * sso:
 *   cookie:
 *     access-token-name: sso_access_token
 *     refresh-token-name: sso_refresh_token
 *     domain: .marschat.online
 *     path: /
 *     secure: true
 *     same-site: Lax
 *     max-age: 7200
 * </pre>
 */
@Component
@ConfigurationProperties(prefix = "sso.cookie")
public class SsoCookieProperties {

    /**
     * Access Token Cookie 名称（必须与前端 auth-components 一致）
     */
    private String accessTokenName = "sso_access_token";

    /**
     * Refresh Token Cookie 名称
     */
    private String refreshTokenName = "sso_refresh_token";

    /**
     * Cookie 域名
     * 设置为 marschat.online 即可覆盖所有子域。
     * 注意：不可带前导点。Tomcat 10 的 Rfc6265CookieProcessor 按 RFC 6265 校验，
     * 前导点会被判为非法域名并抛异常（导致登录 500）。
     */
    private String domain = "marschat.online";

    /**
     * Cookie 路径
     */
    private String path = "/";

    /**
     * 是否仅 HTTPS 传输
     * 生产环境必须为 true
     */
    private boolean secure = true;

    /**
     * SameSite 策略
     * Lax: 允许顶级导航携带 Cookie，防止 CSRF
     */
    private String sameSite = "Lax";

    /**
     * Access Token 过期时间（秒）
     * 默认 2 小时（7200 秒）
     */
    private int maxAge = 7200;

    /**
     * Refresh Token 过期时间（秒）
     * 默认 7 天（604800 秒）
     */
    private int refreshTokenMaxAge = 604800;

    // ========== Getters & Setters ==========

    public String getAccessTokenName() {
        return accessTokenName;
    }

    public void setAccessTokenName(String accessTokenName) {
        this.accessTokenName = accessTokenName;
    }

    public String getRefreshTokenName() {
        return refreshTokenName;
    }

    public void setRefreshTokenName(String refreshTokenName) {
        this.refreshTokenName = refreshTokenName;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public boolean isSecure() {
        return secure;
    }

    public void setSecure(boolean secure) {
        this.secure = secure;
    }

    public String getSameSite() {
        return sameSite;
    }

    public void setSameSite(String sameSite) {
        this.sameSite = sameSite;
    }

    public int getMaxAge() {
        return maxAge;
    }

    public void setMaxAge(int maxAge) {
        this.maxAge = maxAge;
    }

    public int getRefreshTokenMaxAge() {
        return refreshTokenMaxAge;
    }

    public void setRefreshTokenMaxAge(int refreshTokenMaxAge) {
        this.refreshTokenMaxAge = refreshTokenMaxAge;
    }

    @Override
    public String toString() {
        return "SsoCookieProperties{" +
                "accessTokenName='" + accessTokenName + '\'' +
                ", domain='" + domain + '\'' +
                ", path='" + path + '\'' +
                ", secure=" + secure +
                ", sameSite='" + sameSite + '\'' +
                ", maxAge=" + maxAge +
                '}';
    }
}
