package com.marschat.authcenter.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 邮件发送服务（M7）。
 * <p>
 * SMTP 配置来自 application.yml 的 spring.mail.*，值统一走环境变量占位（MAIL_HOST / MAIL_USERNAME /
 * MAIL_PASSWORD / MAIL_FROM），凭证不硬编码。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.from:no-reply@marschat.online}")
    private String from;

    /** 生成 6 位数字验证码 */
    public String generateCode() {
        int code = ThreadLocalRandom.current().nextInt(100000, 1000000); // [100000, 999999]
        return String.valueOf(code);
    }

    /**
     * 发送验证码邮件（简洁 HTML + 纯文本兜底）。
     *
     * @param to   收件邮箱
     * @param code 6 位验证码
     */
    public void sendCode(String to, String code) {
        try {
            var message = mailSender.createMimeMessage();
            var helper = new MimeMessageHelper(message, true, StandardCharsets.UTF_8.name());
            helper.setFrom(from);
            helper.setTo(to);
            helper.setSubject("【统一认证中心】您的验证码");
            helper.setText(buildText(code), buildHtml(code));
            mailSender.send(message);
            log.info("验证码邮件已发送至 {}", to);
        } catch (Exception e) {
            // 邮件发送失败不应阻断业务流程（防枚举已通过统一 200 返回处理），仅告警
            log.warn("发送验证码邮件失败 to={}: {}", to, e.getMessage());
        }
    }

    private String buildText(String code) {
        return "您的验证码为：" + code + "，5 分钟内有效。如非本人操作请忽略。";
    }

    private String buildHtml(String code) {
        return "<div style='font-family:Arial,Helvetica,sans-serif;padding:16px;'>"
                + "<h3>统一认证中心 · 验证码</h3>"
                + "<p>您的验证码为：</p>"
                + "<p style='font-size:24px;font-weight:bold;letter-spacing:4px;color:#2d6cdf;'>"
                + code + "</p>"
                + "<p style='color:#888;'>该验证码 5 分钟内有效。如非本人操作，请忽略本邮件。</p>"
                + "</div>";
    }
}
