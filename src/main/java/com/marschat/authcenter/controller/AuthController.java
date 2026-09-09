package com.marschat.authcenter.controller;

import com.marschat.authcenter.dto.ForgotPasswordRequest;
import com.marschat.authcenter.dto.LoginRequest;
import com.marschat.authcenter.dto.LoginResponse;
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
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserService userService;
    private final SsoCookieUtil ssoCookieUtil;

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

    @GetMapping("/me")
    public Result<LoginResponse> me(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        Long userId = SecurityUtils.getCurrentUserId();
        User user = userService.getProfile(userId);
        String accessToken = authHeader != null && authHeader.startsWith("Bearer ")
                ? authHeader.substring(7) : null;
        return Result.ok(new LoginResponse(accessToken, null, 3600000L, user));
    }
}
