package com.marschat.authcenter.service;

import com.marschat.authcenter.dto.LoginRequest;
import com.marschat.authcenter.dto.LoginResponse;
import com.marschat.authcenter.dto.RefreshRequest;

public interface AuthService {

    LoginResponse login(LoginRequest request);

    void logout(String accessToken);

    LoginResponse refresh(RefreshRequest request);

    /** 邮箱验证码登录：校验 MAIL_LOGIN 验证码 -> 签发令牌（独立端点，不接入 /auth/login 主链路） */
    LoginResponse loginByMail(String email, String code);

    /** 忘记密码：按邮箱发验证码（防枚举，始终返回成功） */
    void forgotPassword(String email);

    /** 重置密码：校验验证码 -> 更新密码 -> 踢下线 */
    void resetPassword(String email, String code, String newPassword);
}
