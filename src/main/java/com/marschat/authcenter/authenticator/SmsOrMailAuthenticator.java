package com.marschat.authcenter.authenticator;

/**
 * 短信 / 邮箱 验证码二次验证器接口骨架（M7 预留扩展点）。
 * <p>
 * 本期不接入 SecurityFilterChain 登录主链路，仅作为未来登录二次验证（2FA）的插件位。
 * 接入方式见 MailCodeAuthenticator 类注释。
 */
public interface SmsOrMailAuthenticator {

    /**
     * 业务类型标识，用于隔离不同场景的 Redis 凭证键（如 MAIL / SMS / MAIL_LOGIN）。
     */
    String bizType();

    /**
     * 校验一次验证请求。
     *
     * @param context 验证上下文（target + code）
     * @return 校验通过返回 true；失败抛出 BusinessException
     */
    boolean authenticate(AuthenticationContext context);
}
