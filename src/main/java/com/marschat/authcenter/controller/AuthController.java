package com.marschat.authcenter.controller;

import com.marschat.authcenter.authenticator.MailCodeAuthenticator;
import com.marschat.authcenter.dto.ForgotPasswordRequest;
import com.marschat.authcenter.dto.LoginRequest;
import com.marschat.authcenter.dto.LoginResponse;
import com.marschat.authcenter.dto.MailLoginRequest;
import com.marschat.authcenter.dto.RefreshRequest;
import com.marschat.authcenter.dto.ResetPasswordRequest;
import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.service.AuthService;
import com.marschat.authcenter.service.UserService;
import com.marschat.authcenter.util.SecurityUtils;
import com.marschat.authcenter.util.SsoCookieUtil;
import com.marschat.common.result.Result;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserService userService;
    private final SsoCookieUtil ssoCookieUtil;
    private final MailCodeAuthenticator mailCodeAuthenticator;

    @PostMapping("/login")
    public Result<LoginResponse> login(@Valid @RequestBody LoginRequest request, HttpServletResponse response) {
        LoginResponse loginResponse = authService.login(request);
        
        // ★ SSO：设置跨域 Cookie，使所有子域共享登录状态
        if (loginResponse.getAccessToken() != null) {
            ssoCookieUtil.setAccessTokenCookie(response, loginResponse.getAccessToken());
            if (loginResponse.getRefreshToken() != null) {
                ssoCookieUtil.setRefreshTokenCookie(response, loginResponse.getRefreshToken());
            }
        }
        
        return Result.ok(loginResponse);
    }

    @PostMapping("/logout")
    public Result<Void> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            HttpServletResponse response) {
        String token = authHeader != null && authHeader.startsWith("Bearer ")
                ? authHeader.substring(7) : null;
        authService.logout(token);
        
        // ★ SSO：清除跨域 Cookie
        ssoCookieUtil.clearSsoCookies(response);
        
        return Result.ok();
    }

    @PostMapping("/refresh")
    public Result<LoginResponse> refresh(@Valid @RequestBody RefreshRequest request, HttpServletResponse response) {
        LoginResponse refreshResponse = authService.refresh(request);
        
        // ★ SSO：刷新 Token 后更新 Cookie
        if (refreshResponse.getAccessToken() != null) {
            ssoCookieUtil.setAccessTokenCookie(response, refreshResponse.getAccessToken());
            if (refreshResponse.getRefreshToken() != null) {
                ssoCookieUtil.setRefreshTokenCookie(response, refreshResponse.getRefreshToken());
            }
        }
        
        return Result.ok(refreshResponse);
    }

    /**
     * 忘记密码：按邮箱发送验证码。
     * 公开端点（无需登录），防枚举——无论邮箱是否存在均返回 200。
     */
    @PostMapping("/forgot-password")
    public Result<Void> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.forgotPassword(request.getEmail());
        return Result.ok();
    }

    /**
     * 重置密码：校验验证码 -> BCrypt 更新密码 -> 踢下线。
     * 公开端点（无需登录）。
     */
    @PostMapping("/reset-password")
    public Result<Void> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request.getEmail(), request.getCode(), request.getNewPassword());
        return Result.ok();
    }

    /**
     * 邮箱验证码登录 - 发送验证码（公开端点）。
     * 复用 MailCodeService 的 MAIL_LOGIN 业务类型，含 60 秒限频 / 5 次锁定。
     */
    @PostMapping("/mail-login/send-code")
    public Result<Void> sendMailLoginCode(@Valid @RequestBody ForgotPasswordRequest request) {
        mailCodeAuthenticator.issueAndSend(request.getEmail());
        return Result.ok();
    }

    /**
     * 邮箱验证码登录 - 校验并签发令牌（公开端点，独立链，不接入 /auth/login 主链路）。
     */
    @PostMapping("/mail-login")
    public Result<LoginResponse> mailLogin(@Valid @RequestBody MailLoginRequest request, HttpServletResponse response) {
        LoginResponse loginResponse = authService.loginByMail(request.getEmail(), request.getCode());

        // ★ SSO：设置跨域 Cookie，使所有子域共享登录状态
        if (loginResponse.getAccessToken() != null) {
            ssoCookieUtil.setAccessTokenCookie(response, loginResponse.getAccessToken());
            if (loginResponse.getRefreshToken() != null) {
                ssoCookieUtil.setRefreshTokenCookie(response, loginResponse.getRefreshToken());
            }
        }

        return Result.ok(loginResponse);
    }

    @GetMapping("/me")
    public Result<LoginResponse> me(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        Long userId = SecurityUtils.getCurrentUserId();
        User user = userService.getProfile(userId);
        String accessToken = authHeader != null && authHeader.startsWith("Bearer ")
                ? authHeader.substring(7) : null;
        return Result.ok(new LoginResponse(accessToken, null, 3600000L, user));
    }

    // ==================== Phase 6：紧密型接入（静默免登 + 统一登出） ====================

    /**
     * 会话探针 —— 供各应用登录页做「静默免登」判定。
     * <p>
     * 返回 {@code authenticated=true} 表示当前浏览器已持有 auth-center 的 IdP 会话，
     * 应用据此自动发起 OIDC 授权即可免密进入（authorize 会瞬间 302 回带 code），
     * 用户无需再点「统一认证登录（SSO）」按钮。
     * <p>
     * ⚠️ 判定依据是**服务端会话里的 Spring Security 上下文**，不是 {@code sso_access_token} Cookie：
     * OIDC 授权流走的是表单登录 + JSESSIONID，那条路径并不写 sso_access_token
     * （该 Cookie 只由 {@code /auth/login}、{@code /auth/mail-login} 这类独立登录写入）。
     * <p>
     * ⚠️ 本端点必须挂在**有会话**（SessionCreationPolicy.IF_REQUIRED）的过滤链上，
     * 否则 STATELESS 链里 SecurityContextHolder 恒为空，将永远返回 false。
     */
    @GetMapping("/session")
    public Result<java.util.Map<String, Object>> session(jakarta.servlet.http.HttpServletRequest request) {
        java.util.Map<String, Object> data = new java.util.LinkedHashMap<>();
        var session = request.getSession(false);
        org.springframework.security.core.Authentication auth =
                org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        boolean authenticated = session != null
                && auth != null
                && auth.isAuthenticated()
                && !(auth instanceof org.springframework.security.authentication.AnonymousAuthenticationToken);
        data.put("authenticated", authenticated);
        data.put("username", authenticated ? auth.getName() : null);
        return Result.ok(data);
    }

    /**
     * 统一登出（SLO）—— 一次跳转完成「清 SSO Cookie + 销毁 IdP 会话」。
     * <p>
     * <b>为什么不直接让应用跳 SAS 的 {@code /connect/logout}：</b>
     * <ol>
     *   <li>SAS 只管自己的会话与授权记录，<b>不会清我们自建的 {@code sso_access_token} Cookie</b>；
     *       残留 Cookie 会让下一次会话探针误判「已登录」。</li>
     *   <li>SAS 要求必须带 {@code id_token_hint}，且 {@code post_logout_redirect_uri} 必须落在
     *       该客户端的 {@code post_logout_redirect_uris} 白名单内，否则直接 400（实测）。</li>
     * </ol>
     * 本端点把两件事合成一次跳转，并对「无 id_token_hint」（独立登录用户 / 会话已过期）降级为
     * 「清 Cookie + 销毁会话 + 直接回跳」，保证任何登录方式都能登出。
     * <p>
     * 参照 OIDC RP-Initiated Logout 1.0：{@code post_logout_redirect_uri} + 可选 {@code state}。
     */
    @GetMapping("/slo")
    public void slo(
            @RequestParam(value = "post_logout_redirect_uri", required = false) String postLogoutRedirectUri,
            @RequestParam(value = "id_token_hint", required = false) String idTokenHint,
            @RequestParam(value = "state", required = false) String state,
            jakarta.servlet.http.HttpServletRequest request,
            HttpServletResponse response) throws java.io.IOException {

        // 1) 清跨域 SSO Cookie（任何登录方式都做）
        ssoCookieUtil.clearSsoCookies(response);

        // ★ 防开放重定向：回跳地址必须落在本平台域名/内网开发地址白名单内，否则一律丢弃。
        //   有 hint 时 SAS 也会校验一次（按客户端 post_logout_redirect_uris），
        //   但无 hint 分支是「我们自己 302」，不校验就是公开的跳板，必须自己把关。
        String safeRedirect = isAllowedRedirect(postLogoutRedirectUri) ? postLogoutRedirectUri : null;

        boolean hasHint = idTokenHint != null && !idTokenHint.isBlank();
        if (hasHint) {
            // 2a) 有 id_token_hint：交给 SAS 销毁 IdP 会话 + 校验回跳白名单
            // ★ 必须用绝对地址：sendRedirect 的 Location 由容器按 request 推断，
            //   经 nginx 反代时会被推断成 http://（scheme 降级），
            //   在「HSTS / Secure Cookie」下这一步会丢 JSESSIONID 导致登出失败（2026-09-11 实测）。
            StringBuilder sb = new StringBuilder(publicBaseUrl(request)).append("/connect/logout");
            sb.append("?id_token_hint=").append(enc(idTokenHint));
            if (safeRedirect != null) {
                sb.append("&post_logout_redirect_uri=").append(enc(safeRedirect));
            }
            if (state != null && !state.isBlank()) {
                sb.append("&state=").append(enc(state));
            }
            response.sendRedirect(sb.toString());
            return;
        }

        // 2b) 无 id_token_hint：独立登录 / 会话已失效 → 直接销毁会话并回跳
        try {
            var session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
        } catch (Exception e) {
            log.warn("SLO 会话销毁失败（不影响回跳）: {}", e.getMessage());
        }
        response.sendRedirect(safeRedirect != null ? safeRedirect : publicBaseUrl(request) + "/login.html");
    }

    /**
     * 还原「用户浏览器眼中」的本服务基地址（scheme://host[:port]）。
     * <p>
     * 反代链路：浏览器 → 腾讯云2号 nginx(TLS 终结) → mykng nginx → 容器。
     * 容器看到的 request 是明文 http，必须靠 {@code X-Forwarded-Proto/Host} 还原，
     * 否则 sendRedirect 会把 https 降级成 http。
     */
    private static String publicBaseUrl(jakarta.servlet.http.HttpServletRequest request) {
        String proto = firstNonBlank(
                request.getHeader("X-Forwarded-Proto"),
                request.getScheme());
        // X-Forwarded-Proto 可能是 "https,http"（多级代理链），取最左
        if (proto != null && proto.contains(",")) {
            proto = proto.substring(0, proto.indexOf(',')).trim();
        }
        String host = firstNonBlank(
                request.getHeader("X-Forwarded-Host"),
                request.getHeader("Host"));
        if (host != null && host.contains(",")) {
            host = host.substring(0, host.indexOf(',')).trim();
        }
        if (host == null || host.isBlank()) {
            host = request.getServerName();
            int port = request.getServerPort();
            boolean defaultPort = ("https".equalsIgnoreCase(proto) && port == 443)
                    || ("http".equalsIgnoreCase(proto) && port == 80);
            if (!defaultPort) {
                host = host + ":" + port;
            }
        }
        return (proto == null || proto.isBlank() ? "https" : proto.toLowerCase()) + "://" + host;
    }

    /**
     * 回跳地址白名单：本平台域名（*.marschat.online）+ 内网/本机开发地址。
     * 解析失败或不在白名单 → false（调用方降级为默认回跳）。
     */
    private static boolean isAllowedRedirect(String uri) {
        if (uri == null || uri.isBlank()) {
            return false;
        }
        try {
            java.net.URI u = java.net.URI.create(uri.trim());
            String scheme = u.getScheme();
            if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                return false;
            }
            String host = u.getHost();
            if (host == null || host.isBlank()) {
                return false;
            }
            host = host.toLowerCase();
            if (host.equals("marschat.online") || host.endsWith(".marschat.online")) {
                return true;
            }
            // 本机 / 内网开发地址（本地联调、局域网直连）
            if (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("::1")
                    || host.equals("[::1]")) {
                return true;
            }
            // RFC 1918 私网：10/8、192.168/16、172.16/12
            String[] octets = host.split("\\.");
            if (octets.length == 4 && isNumericOctets(octets)) {
                int a = Integer.parseInt(octets[0]);
                int b = Integer.parseInt(octets[1]);
                if (a == 10 || a == 192 && b == 168 || a == 172 && b >= 16 && b <= 31) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isNumericOctets(String[] parts) {
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3) {
                return false;
            }
            for (int i = 0; i < p.length(); i++) {
                if (!Character.isDigit(p.charAt(i))) {
                    return false;
                }
            }
        }
        return true;
    }

    private static String firstNonBlank(String a, String b) {
        return (a != null && !a.isBlank()) ? a : b;
    }

    /** URL 编码（UTF-8），供 SLO 拼装回跳参数 */
    private static String enc(String v) {
        return java.net.URLEncoder.encode(v, java.nio.charset.StandardCharsets.UTF_8);
    }
}
