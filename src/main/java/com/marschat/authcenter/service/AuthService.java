package com.marschat.authcenter.service;

import com.marschat.authcenter.dto.LoginRequest;
import com.marschat.authcenter.dto.LoginResponse;
import com.marschat.authcenter.dto.RefreshRequest;

public interface AuthService {

    LoginResponse login(LoginRequest request);

    void logout(String accessToken);

    LoginResponse refresh(RefreshRequest request);

    /** 忘记密码：按邮箱发验证码（防枚举，始终返回成功） */
    void forgotPassword(String email);

    /** 重置密码：校验验证码 -> 更新密码 -> 踢下线 */
    void resetPassword(String email, String code, String newPassword);
}
