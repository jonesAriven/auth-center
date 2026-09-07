package com.marschat.authcenter.authenticator;

import lombok.Data;

/**
 * 二次验证上下文（Authenticator 扩展点，M7 预留）。
 * <p>
 * 未来登录主链路接入短信/邮箱二次验证时，由认证过滤器构造该上下文并交由
 * {@link SmsOrMailAuthenticator#authenticate(AuthenticationContext)} 校验。
 */
@Data
public class AuthenticationContext {

    /** 验证目标：邮箱或手机号 */
    private String target;

    /** 用户提交的验证码 */
    private String code;

    /** 可选：关联 userId，便于审计 */
    private Long userId;
}
