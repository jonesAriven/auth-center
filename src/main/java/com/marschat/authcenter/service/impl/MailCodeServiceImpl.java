package com.marschat.authcenter.service.impl;

import com.marschat.authcenter.service.MailCodeService;
import com.marschat.authcenter.service.MailService;
import com.marschat.common.exception.BusinessException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class MailCodeServiceImpl implements MailCodeService {

    private final StringRedisTemplate stringRedisTemplate;
    private final MailService mailService;

    /** 验证码前缀（与现有 RS256 JWK 持久化键 auth:oidc:rsa-jwk 同命名空间） */
    private static final String KEY_PREFIX = "auth:mail:";

    /** 验证码 TTL：5 分钟 */
    private static final long CODE_TTL_SECONDS = 5 * 60L;
    /** 同 bizType+目标 60 秒内禁止重发 */
    private static final long RATE_TTL_SECONDS = 60L;
    /** 连续错误锁定 15 分钟 */
    private static final long LOCK_TTL_SECONDS = 15 * 60L;
    /** 连续错误上限 */
    private static final int MAX_FAIL = 5;

    private String codeKey(String bizType, String target) {
        return KEY_PREFIX + "code:" + bizType + ":" + target;
    }

    private String rateKey(String bizType, String target) {
        return KEY_PREFIX + "ratelimit:" + bizType + ":" + target;
    }

    private String failKey(String bizType, String target) {
        return KEY_PREFIX + "fail:" + bizType + ":" + target;
    }

    private String lockKey(String bizType, String target) {
        return KEY_PREFIX + "lock:" + bizType + ":" + target;
    }

    @Override
    public String issue(String bizType, String target) {
        // 60 秒限频
        if (Boolean.TRUE.equals(stringRedisTemplate.hasKey(rateKey(bizType, target)))) {
            throw new BusinessException("验证码发送过于频繁，请 60 秒后再试");
        }

        String code = mailService.generateCode();
        // 写入验证码（覆盖旧码，一次性）
        stringRedisTemplate.opsForValue().set(codeKey(bizType, target), code, CODE_TTL_SECONDS, TimeUnit.SECONDS);
        // 新一轮发送，重置错误计数
        stringRedisTemplate.delete(failKey(bizType, target));
        // 写入限频标记
        stringRedisTemplate.opsForValue().set(rateKey(bizType, target), "1", RATE_TTL_SECONDS, TimeUnit.SECONDS);

        log.debug("已生成邮箱验证码 bizType={}, target={}", bizType, target);
        return code;
    }

    @Override
    public void verify(String bizType, String target, String inputCode) {
        // 锁定优先
        if (Boolean.TRUE.equals(stringRedisTemplate.hasKey(lockKey(bizType, target)))) {
            throw new BusinessException("尝试次数过多，请 15 分钟后再试");
        }

        String stored = stringRedisTemplate.opsForValue().get(codeKey(bizType, target));
        if (stored == null) {
            incrFail(bizType, target);
            throw new BusinessException("验证码错误或已过期");
        }
        if (!stored.equals(inputCode)) {
            incrFail(bizType, target);
            throw new BusinessException("验证码错误");
        }

        // 成功：一次性删除凭证与错误计数
        stringRedisTemplate.delete(codeKey(bizType, target));
        stringRedisTemplate.delete(failKey(bizType, target));
    }

    /** 错误计数 +1，达到上限则锁定 15 分钟 */
    private void incrFail(String bizType, String target) {
        String fk = failKey(bizType, target);
        Long count = stringRedisTemplate.opsForValue().increment(fk);
        if (count != null && count == 1) {
            // 首次写入需设置 15 分钟过期（与锁定窗口对齐）
            stringRedisTemplate.expire(fk, LOCK_TTL_SECONDS, TimeUnit.SECONDS);
        }
        if (count != null && count >= MAX_FAIL) {
            stringRedisTemplate.opsForValue().set(lockKey(bizType, target), "1", LOCK_TTL_SECONDS, TimeUnit.SECONDS);
            stringRedisTemplate.delete(fk);
            log.warn("邮箱验证码连续错误达上限，已锁定 bizType={}, target={}", bizType, target);
        }
    }
}
