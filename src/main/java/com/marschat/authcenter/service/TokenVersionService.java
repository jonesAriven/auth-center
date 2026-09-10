package com.marschat.authcenter.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

/**
 * 基于 Redis 的 token 版本号（不占用 user 表列）。
 * <p>
 * 禁用/删除用户时 {@link #bump(Long)} 使版本 +1，已签发的 access token 携带旧版本号，
 * {@link com.marschat.authcenter.security.JwtAuthenticationFilter} 校验时发现旧于当前版本即视为失效，
 * 从而实现「禁用即踢下线」且不修改 user 表结构。
 *
 * <p><b>降级策略（重要）</b>：auth-center 是 12 个应用的 SSO 枢纽，Redis 抖动不应导致所有登录/刷新 500。
 * 因此读写异常一律降级：
 * <ul>
 *   <li>{@link #currentVersion} 异常 → 返回 0（按无版本号处理，签发/校验均放行）；</li>
 *   <li>{@link #bump} 异常 → 仅记日志（踢下线能力暂时失效，但用户状态变更本身已落库，
 *       且 refresh token 已被回收，重新登录会被 status 校验拦住）。</li>
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenVersionService {

    private final StringRedisTemplate stringRedisTemplate;

    private static final String KEY_PREFIX = "auth:tv:";

    /** 当前 token 版本（未设置或 Redis 不可用则 0） */
    public long currentVersion(Long userId) {
        try {
            String v = stringRedisTemplate.opsForValue().get(KEY_PREFIX + userId);
            return v == null ? 0L : Long.parseLong(v);
        } catch (Exception e) {
            log.warn("读取 token 版本失败，降级为 0（Redis 可能不可用）userId={}", userId, e);
            return 0L;
        }
    }

    /** 使该用户已签发的所有 token 立即失效（版本 +1）；Redis 不可用则降级为仅记日志 */
    public void bump(Long userId) {
        try {
            stringRedisTemplate.opsForValue().increment(KEY_PREFIX + userId, 1);
        } catch (Exception e) {
            log.warn("递增 token 版本失败，踢下线能力暂时失效（Redis 可能不可用）userId={}", userId, e);
        }
    }
}
