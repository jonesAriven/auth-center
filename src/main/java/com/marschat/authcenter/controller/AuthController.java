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

        boolean hasHint = idTokenHint != null && !idTokenHint.isBlank();
        if (hasHint) {
            // 2a) 有 id_token_hint：交给 SAS 销毁 IdP 会话 + 校验回跳白名单
            //     用相对路径，公网域与内网直连都能落到同一个 SAS 端点
            StringBuilder sb = new StringBuilder("/connect/logout");
            sb.append("?id_token_hint=").append(enc(idTokenHint));
            if (postLogoutRedirectUri != null && !postLogoutRedirectUri.isBlank()) {
                sb.append("&post_logout_redirect_uri=").append(enc(postLogoutRedirectUri));
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
        response.sendRedirect(
                postLogoutRedirectUri != null && !postLogoutRedirectUri.isBlank()
                        ? postLogoutRedirectUri : "/login.html");
    }

    /** URL 编码（UTF-8），供 SLO 拼装回跳参数 */
    private static String enc(String v) {
        return java.net.URLEncoder.encode(v, java.nio.charset.StandardCharsets.UTF_8);
    }
}
