package com.marschat.authcenter.config;

import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.mapper.UserMapper;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.UUID;

/**
 * 统一认证中心（auth-center Phase 1）：
 * RS256 密钥（Nimbus 生成，Redis 持久化 JWK JSON，重启不失效）+ JWKS 数据源 + OIDC token 定制（uid/username/realm/role）。
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private static final String RSA_JWK_REDIS = "auth:oidc:rsa-jwk";

    private final StringRedisTemplate stringRedisTemplate;
    private final UserMapper userMapper;

    @Value("${marschat.auth.issuer:http://auth-center:8085}")
    private String issuer;

    /** RS256 签名密钥：首次由 Nimbus 生成（3072 位），JWK JSON 存 Redis，重启复用 */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = loadOrCreateJwk();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /** 资源服务器侧验 RS256 token 用（userinfo 等端点） */
    @Bean
    public org.springframework.security.oauth2.jwt.JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    /** 客户端注册走 JDBC（DatabaseInitializer 建表并播种 marschat-portal） */
    @Bean
    public org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository registeredClientRepository(org.springframework.jdbc.core.JdbcTemplate jdbcTemplate) {
        return new org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizationService(
            org.springframework.jdbc.core.JdbcTemplate jdbcTemplate,
            org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository clients) {
        return new org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService(jdbcTemplate, clients);
    }

    @Bean
    public org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService authorizationConsentService(
            org.springframework.jdbc.core.JdbcTemplate jdbcTemplate,
            org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository clients) {
        return new org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService(jdbcTemplate, clients);
    }

    /** OIDC access token 注入业务 claims：uid/username/realm/role */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                return;
            }
            String principalName = context.getPrincipal().getName();
            User user = resolveUser(principalName);
            JwtClaimsSet.Builder claims = context.getClaims();
            if (user != null) {
                claims.claim("uid", String.valueOf(user.getId()));
                claims.claim("username", user.getUsername());
                claims.claim("realm", user.getRealmId() == null ? "kb" : user.getRealmId());
                claims.claim("role", user.getRole() == null ? "user" : user.getRole());
            } else {
                claims.claim("username", principalName);
            }
        };
    }

    private User resolveUser(String principalName) {
        try {
            Long id = Long.parseLong(principalName);
            return userMapper.selectById(id);
        } catch (NumberFormatException e) {
            return userMapper.selectOne(new LambdaQueryWrapper<User>().eq(User::getUsername, principalName));
        }
    }

    private RSAKey loadOrCreateJwk() {
        try {
            String stored = stringRedisTemplate.opsForValue().get(RSA_JWK_REDIS);
            if (stored != null && !stored.isBlank()) {
                return RSAKey.parse(stored);
            }
        } catch (Exception e) {
            log.warn("读取 Redis 中的 RS256 JWK 失败，将重新生成: {}", e.getMessage());
        }
        try {
            RSAKey generated = new RSAKeyGenerator(3072)
                    .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            stringRedisTemplate.opsForValue().set(RSA_JWK_REDIS, generated.toJSONString());
            log.info("已生成并持久化新的 RS256 JWK（Redis）");
            return generated;
        } catch (Exception e) {
            throw new IllegalStateException("生成 RS256 JWK 失败", e);
        }
    }
}
