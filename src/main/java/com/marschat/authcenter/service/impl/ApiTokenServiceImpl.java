package com.marschat.authcenter.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.marschat.authcenter.dto.ApiTokenRequest;
import com.marschat.authcenter.dto.ApiTokenResponse;
import com.marschat.authcenter.entity.ApiToken;
import com.marschat.authcenter.mapper.ApiTokenMapper;
import com.marschat.authcenter.service.ApiTokenService;
import com.marschat.authcenter.util.CryptoUtil;
import com.marschat.common.exception.BusinessException;
import com.marschat.common.exception.NotFoundException;
import com.marschat.common.page.PageResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class ApiTokenServiceImpl implements ApiTokenService {

    private final ApiTokenMapper apiTokenMapper;
    private final CryptoUtil cryptoUtil;

    @Value("${api-token.prefix}")
    private String tokenPrefix;

    @Value("${api-token.expire-days}")
    private int defaultExpireDays;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    @Override
    @Transactional
    public ApiTokenResponse create(Long userId, ApiTokenRequest request) {
        // 生成随机 Token 明文: 前缀 + 32位十六进制随机串
        String rawToken = tokenPrefix + generateRandomHex(32);
        String encrypted = cryptoUtil.encrypt(rawToken);

        ApiToken token = new ApiToken();
        token.setUserId(userId);
        token.setName(request.getName());
        token.setTokenEncrypted(encrypted);
        token.setTokenPrefix(rawToken.substring(0, Math.min(rawToken.length(), 12)) + "****");
        token.setScope(request.getScope() != null ? request.getScope() : "");
        token.setStatus(0); // 0=启用
        token.setExpireAt(request.getExpireAt() != null ? request.getExpireAt()
                : LocalDateTime.now().plusDays(defaultExpireDays));

        apiTokenMapper.insert(token);

        log.info("创建 API Token userId={}, tokenId={}, name={}", userId, token.getId(), request.getName());

        return new ApiTokenResponse(
                token.getId(),
                token.getName(),
                rawToken,
                token.getTokenPrefix(),
                token.getScope(),
                token.getExpireAt(),
                token.getCreatedAt()
        );
    }

    @Override
    public PageResult<ApiToken> list(Long userId, int page, int size) {
        Page<ApiToken> pageObj = new Page<>(page, size);
        LambdaQueryWrapper<ApiToken> wrapper = new LambdaQueryWrapper<ApiToken>()
                .eq(ApiToken::getUserId, userId)
                .orderByDesc(ApiToken::getCreatedAt);
        Page<ApiToken> result = apiTokenMapper.selectPage(pageObj, wrapper);

        // 清除加密值，不返回给前端
        result.getRecords().forEach(t -> t.setTokenEncrypted(null));

        return PageResult.of(result.getRecords(), result.getTotal(), page, size);
    }

    @Override
    @Transactional
    public void delete(Long userId, Long tokenId) {
        ApiToken token = getAndCheckOwnership(userId, tokenId);
        apiTokenMapper.deleteById(token.getId());
        log.info("删除 API Token userId={}, tokenId={}", userId, tokenId);
    }

    @Override
    @Transactional
    public void toggleStatus(Long userId, Long tokenId) {
        ApiToken token = getAndCheckOwnership(userId, tokenId);
        token.setStatus(token.getStatus() == 0 ? 1 : 0);
        apiTokenMapper.updateById(token);
        log.info("切换 API Token 状态 userId={}, tokenId={}, status={}", userId, tokenId, token.getStatus());
    }

    @Override
    public ApiToken verify(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new BusinessException(401, "API Token 不能为空");
        }

        // 遍历所有有效 Token，逐个解密比对（Token 加密存储，无法直接按明文查询）
        // 优化：使用 tokenPrefix 做初步过滤
        String prefixHint = rawToken.length() > 12 ? rawToken.substring(0, 12) : rawToken;

        List<ApiToken> candidates = apiTokenMapper.selectList(
                new LambdaQueryWrapper<ApiToken>()
                        .likeRight(ApiToken::getTokenPrefix, prefixHint)
                        .eq(ApiToken::getStatus, 0)
        );

        for (ApiToken candidate : candidates) {
            try {
                String decrypted = cryptoUtil.decrypt(candidate.getTokenEncrypted());
                if (rawToken.equals(decrypted)) {
                    // 检查是否过期
                    if (candidate.getExpireAt() != null
                            && candidate.getExpireAt().isBefore(LocalDateTime.now())) {
                        throw new BusinessException(401, "API Token 已过期");
                    }
                    // 更新最后使用时间
                    candidate.setLastUsedAt(LocalDateTime.now());
                    apiTokenMapper.updateById(candidate);
                    return candidate;
                }
            } catch (BusinessException e) {
                throw e;
            } catch (Exception e) {
                log.warn("API Token 解密失败 tokenId={}: {}", candidate.getId(), e.getMessage());
            }
        }

        throw new BusinessException(401, "无效的 API Token");
    }

    @Override
    public List<ApiToken> listByUser(Long userId) {
        return apiTokenMapper.selectList(
                new LambdaQueryWrapper<ApiToken>()
                        .eq(ApiToken::getUserId, userId)
                        .eq(ApiToken::getStatus, 0)
                        .orderByDesc(ApiToken::getCreatedAt));
    }

    private ApiToken getAndCheckOwnership(Long userId, Long tokenId) {
        ApiToken token = apiTokenMapper.selectById(tokenId);
        if (token == null) {
            throw new NotFoundException("API Token", tokenId);
        }
        if (!token.getUserId().equals(userId)) {
            throw new BusinessException(403, "无权操作此 Token");
        }
        return token;
    }

    private String generateRandomHex(int length) {
        byte[] bytes = new byte[length / 2];
        SECURE_RANDOM.nextBytes(bytes);
        char[] chars = new char[length];
        for (int i = 0; i < bytes.length; i++) {
            chars[i * 2] = HEX[(bytes[i] >> 4) & 0x0F];
            chars[i * 2 + 1] = HEX[bytes[i] & 0x0F];
        }
        return new String(chars);
    }
}
