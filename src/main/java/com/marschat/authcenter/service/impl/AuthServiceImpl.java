package com.marschat.authcenter.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.marschat.authcenter.dto.LoginRequest;
import com.marschat.authcenter.dto.LoginResponse;
import com.marschat.authcenter.dto.RefreshRequest;
import com.marschat.authcenter.entity.JwtBlacklist;
import com.marschat.authcenter.entity.RefreshToken;
import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.mapper.JwtBlacklistMapper;
import com.marschat.authcenter.mapper.RefreshTokenMapper;
import com.marschat.authcenter.mapper.UserMapper;
import com.marschat.authcenter.security.JwtTokenProvider;
import com.marschat.authcenter.service.AuthService;
import com.marschat.authcenter.service.MailCodeService;
import com.marschat.authcenter.service.MailService;
import com.marschat.common.event.AppEvent;
import com.marschat.common.exception.BusinessException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserMapper userMapper;
    private final RefreshTokenMapper refreshTokenMapper;
    private final JwtBlacklistMapper jwtBlacklistMapper;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate<String, Object> redisTemplate;
    private final MailService mailService;
    private final MailCodeService mailCodeService;

    /** 忘记密码 / 重置密码 业务类型标识 */
    private static final String BIZ_RESET_PASSWORD = "RESET_PASSWORD";

    private static final String EVENT_CHANNEL = "kb:events";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    @Transactional
    public LoginResponse login(LoginRequest request) {
        User user = userMapper.selectOne(
                new LambdaQueryWrapper<User>().eq(User::getUsername, request.getUsername()));
        if (user == null) {
            throw new BusinessException("用户名或密码错误");
        }
        if (user.getStatus() == 0) {
            throw new BusinessException("用户已被禁用");
        }
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BusinessException("用户名或密码错误");
        }

        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getUsername());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId());

        RefreshToken rt = new RefreshToken();
        rt.setUserId(user.getId());
        rt.setToken(refreshToken);
        rt.setExpireAt(LocalDateTime.now().plusDays(7));
        refreshTokenMapper.insert(rt);

        // 通过 Redis Pub/Sub 发布登录事件（替代跨服务的 OperationLogService）
        publishEvent("user.login", user.getId(), Map.of("username", user.getUsername()));

        log.info("用户登录成功 userId={}, username={}", user.getId(), user.getUsername());
        user.setPassword(null);
        return new LoginResponse(accessToken, refreshToken, jwtTokenProvider.getAccessTokenExpiration(), user);
    }

    @Override
    @Transactional
    public void logout(String accessToken) {
        if (accessToken == null) {
            return;
        }

        if (jwtTokenProvider.validateToken(accessToken)) {
            JwtBlacklist blacklist = new JwtBlacklist();
            blacklist.setToken(accessToken);
            blacklist.setExpireAt(jwtTokenProvider.getExpirationFromToken(accessToken)
                    .toInstant().atZone(java.time.ZoneId.systemDefault()).toLocalDateTime());
            jwtBlacklistMapper.insert(blacklist);

            Long userId = jwtTokenProvider.getUserIdFromToken(accessToken);
            publishEvent("user.logout", userId, Map.of());
            log.info("用户登出成功 userId={}", userId);
        }
    }

    @Override
    @Transactional
    public LoginResponse refresh(RefreshRequest request) {
        String refreshToken = request.getRefreshToken();

        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new BusinessException(401, "RefreshToken无效或已过期");
        }

        String type = jwtTokenProvider.getTokenType(refreshToken);
        if (!"refresh".equals(type)) {
            throw new BusinessException(401, "无效的Token类型");
        }

        Long userId = jwtTokenProvider.getUserIdFromToken(refreshToken);

        List<RefreshToken> tokens = refreshTokenMapper.selectList(
                new LambdaQueryWrapper<RefreshToken>()
                        .eq(RefreshToken::getUserId, userId)
                        .eq(RefreshToken::getToken, refreshToken));
        RefreshToken storedToken = tokens.stream().findFirst().orElse(null);
        if (storedToken == null) {
            throw new BusinessException(401, "RefreshToken不存在");
        }

        User user = userMapper.selectById(userId);
        if (user == null || user.getStatus() == 0) {
            throw new BusinessException(401, "用户不存在或已被禁用");
        }

        // 删除该 refresh token 对应的所有记录（防止重复 token 残留导致下次 selectOne 抛 TooManyResultsException）
        refreshTokenMapper.delete(
                new LambdaQueryWrapper<RefreshToken>()
                        .eq(RefreshToken::getUserId, userId)
                        .eq(RefreshToken::getToken, refreshToken));

        String newAccessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getUsername());
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(user.getId());

        RefreshToken rt = new RefreshToken();
        rt.setUserId(user.getId());
        rt.setToken(newRefreshToken);
        rt.setExpireAt(LocalDateTime.now().plusDays(7));
        refreshTokenMapper.insert(rt);

        user.setPassword(null);
        return new LoginResponse(newAccessToken, newRefreshToken, jwtTokenProvider.getAccessTokenExpiration(), user);
    }

    @Override
    public void forgotPassword(String email) {
        // 防枚举：始终返回成功。仅当存在该邮箱用户时才真正发码
        User user = userMapper.selectOne(new LambdaQueryWrapper<User>()
                .eq(User::getEmail, email)
                .orderByDesc(User::getId)
                .last("LIMIT 1"));
        if (user == null || user.getEmail() == null || user.getEmail().isBlank()) {
            log.warn("忘记密码：邮箱无对应用户或用户邮箱为空，已静默返回 email={}", email);
            return;
        }
        String code = mailCodeService.issue(BIZ_RESET_PASSWORD, email);
        mailService.sendCode(email, code);
    }

    @Override
    @Transactional
    public void resetPassword(String email, String code, String newPassword) {
        // 先校验验证码（一次性，失败/锁定均抛异常）；不存在的用户也会在 verify 抛错，不泄露账户是否存在
        mailCodeService.verify(BIZ_RESET_PASSWORD, email, code);

        User user = userMapper.selectOne(new LambdaQueryWrapper<User>()
                .eq(User::getEmail, email)
                .orderByDesc(User::getId)
                .last("LIMIT 1"));
        if (user == null) {
            throw new BusinessException("验证码错误或已过期");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userMapper.updateById(user);

        // 踢下线：清空该用户所有 refresh_token 记录
        refreshTokenMapper.delete(new LambdaQueryWrapper<RefreshToken>()
                .eq(RefreshToken::getUserId, user.getId()));

        publishEvent("user.password.reset", user.getId(), Map.of("email", email));
        log.info("密码重置成功 userId={}, email={}", user.getId(), email);
    }

    /**
     * 通过 Redis Pub/Sub 发布事件，替代原单体中的 OperationLogService.log()
     */
    private void publishEvent(String event, Long userId, Map<String, Object> payload) {
        try {
            AppEvent kbEvent = new AppEvent(event, userId, payload);
            kbEvent.setSource("auth-center");
            redisTemplate.convertAndSend(EVENT_CHANNEL, objectMapper.writeValueAsString(kbEvent));
        } catch (Exception e) {
            log.warn("发布事件失败 event={}, userId={}: {}", event, userId, e.getMessage());
        }
    }
}
