package com.marschat.authcenter.authenticator;

import com.marschat.authcenter.service.MailCodeService;
import com.marschat.authcenter.service.MailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * 邮箱验证码验证器实现（M7 预留扩展点的首个具体实现）。
 * <p>
 * 复用 {@link MailCodeService}（Redis 一次性凭证 / 限频 / 锁定）与 {@link MailService}（发码），
 * 与「忘记密码」共用同一套 Redis 凭证体系，仅 bizType 不同（MAIL_LOGIN）。
 *
 * <h3>接入登录主链路（未来 2FA）示例</h3>
 * <pre>
 * // 1) 在 SecurityFilterChain 的登录成功处理器 / 自定义 AuthenticationProvider 中：
 * AuthenticationContext ctx = new AuthenticationContext();
 * ctx.setTarget(email);
 * ctx.setCode(userSubmittedCode);
 * boolean ok = mailCodeAuthenticator.authenticate(ctx);
 * if (!ok) { throw new BadCredentialsException("邮箱验证码错误"); }
 *
 * // 2) 登录前如需下发验证码，可调用：mailCodeAuthenticator.issueAndSend(email)
 * </pre>
 * 本期不启用，避免影响现有 /auth/login 主链路。
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MailCodeAuthenticator implements SmsOrMailAuthenticator {

    private final MailCodeService mailCodeService;
    private final MailService mailService;

    /** 登录二次验证业务类型（与 RESET_PASSWORD 隔离） */
    public static final String BIZ_MAIL_LOGIN = "MAIL_LOGIN";

    @Override
    public String bizType() {
        return "MAIL";
    }

    @Override
    public boolean authenticate(AuthenticationContext context) {
        mailCodeService.verify(BIZ_MAIL_LOGIN, context.getTarget(), context.getCode());
        return true;
    }

    /** 登录二次验证下发验证码（供未来接入时调用） */
    public String issueAndSend(String email) {
        String code = mailCodeService.issue(BIZ_MAIL_LOGIN, email);
        mailService.sendCode(email, code);
        return code;
    }
}
