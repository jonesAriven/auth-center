package com.marschat.authcenter.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.Yaml;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * clients.yml L1 加载器（Phase 3 配置化接入，R5=第一版 L1）。
 *
 * <p>启动时读取 classpath 的 {@code clients.yml}（由 devtools {@code scripts/gen-from-registry.py}
 * 从 apps-registry.yml 派生，AUTO-GENERATED）批量 upsert OIDC 客户端，**替代**
 * DatabaseInitializer 中 5 个 seedXxx 硬编码方法（约 340 行内网 IP 写死 Java）。
 *
 * <p>幂等语义与既有 seed 完全一致：客户端已存在时仅当 redirect/postLogout 白名单
 * 缺项才更新（containsAll 对比）——不覆盖运行期可能被修改的其他属性。
 * 新应用接入 = apps-registry.yml 加段 + 跑生成器 + 重启，全程不改 Java。
 *
 * <p>⚠️ 单条加载失败仅 WARN 跳过：种子失败不阻断启动（与既有 seed 行为一致）。
 */
@Slf4j
@Component
public class ClientsYmlLoader implements ApplicationRunner {

    private final JdbcRegisteredClientRepository repository;
    private final PasswordEncoder passwordEncoder;

    public ClientsYmlLoader(JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder) {
        this.repository = new JdbcRegisteredClientRepository(jdbcTemplate);
        this.passwordEncoder = passwordEncoder;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void run(ApplicationArguments args) {
        try {
            ClassPathResource resource = new ClassPathResource("clients.yml");
            if (!resource.exists()) {
                log.warn("classpath 无 clients.yml，跳过 L1 加载（沿用库内既有客户端）");
                return;
            }
            Map<String, Object> root = new Yaml().load(
                    new java.io.InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8));
            load(root);
        } catch (Exception e) {
            log.warn("clients.yml 加载失败: {}", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    void load(Map<String, Object> root) {
        Object clientsObj = root.get("clients");
        if (!(clientsObj instanceof List<?> clients)) {
            log.warn("clients.yml 缺 clients 段，跳过");
            return;
        }
        int created = 0, updated = 0, unchanged = 0;
        for (Object o : clients) {
            try {
                Map<String, Object> c = (Map<String, Object>) o;
                String clientId = String.valueOf(c.get("client-id"));
                String type = String.valueOf(c.getOrDefault("type", "public"));
                List<String> redirects = (List<String>) c.get("redirect-uris");
                // yml 中 key 存在但值为空（`key:` 无值）时 snakeyaml 解析为 null——getOrDefault 不生效
                List<String> postLogouts = c.get("post-logout-redirect-uris") instanceof List<?> pl
                        ? (List<String>) pl : List.of();

                RegisteredClient existing = repository.findByClientId(clientId);
                if (existing == null) {
                    RegisteredClient.Builder b = RegisteredClient.withId(UUID.randomUUID().toString())
                            .clientId(clientId)
                            .clientName(String.valueOf(c.getOrDefault("name", clientId)))
                            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                            .redirectUris(r -> r.addAll(redirects))
                            .clientSettings(ClientSettings.builder()
                                    .requireAuthorizationConsent(Bool(c.get("require-consent"), false))
                                    .requireProofKey("public".equals(type))
                                    .build())
                            .tokenSettings(TokenSettings.builder()
                                    .accessTokenTimeToLive(Duration.ofMinutes(Long.parseLong(
                                            String.valueOf(c.getOrDefault("access-token-ttl-minutes", "30")))))
                                    .refreshTokenTimeToLive(Duration.ofDays(Long.parseLong(
                                            String.valueOf(c.getOrDefault("refresh-token-ttl-days", "7")))))
                                    .reuseRefreshTokens(Bool(c.get("reuse-refresh-tokens"), false))
                                    .build());
                    if ("confidential".equals(type)) {
                        b.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                                .clientSecret(passwordEncoder.encode(String.valueOf(c.get("secret"))));
                    } else {
                        b.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
                    }
                    Object scopes = c.get("scopes");
                    if (scopes instanceof List<?> sl && !sl.isEmpty()) {
                        sl.forEach(s -> b.scope(String.valueOf(s)));
                    } else {
                        b.scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE);
                    }
                    if (!postLogouts.isEmpty()) {
                        b.postLogoutRedirectUris(r -> r.addAll(postLogouts));
                    }
                    repository.save(b.build());
                    created++;
                    log.info("clients.yml 种子客户端 {}（{}）已就绪", clientId, type);
                    continue;
                }
                boolean needUpdate = false;
                RegisteredClient.Builder ub = RegisteredClient.from(existing);
                if (!existing.getRedirectUris().containsAll(redirects)) {
                    ub.redirectUris(r -> {
                        r.clear();
                        r.addAll(redirects);
                    });
                    needUpdate = true;
                }
                if (!postLogouts.isEmpty() && !existing.getPostLogoutRedirectUris().containsAll(postLogouts)) {
                    ub.postLogoutRedirectUris(r -> {
                        r.clear();
                        r.addAll(postLogouts);
                    });
                    needUpdate = true;
                }
                if (needUpdate) {
                    repository.save(ub.build());
                    updated++;
                    log.info("clients.yml 幂等补齐客户端 {} 白名单", clientId);
                } else {
                    unchanged++;
                }
            } catch (Exception e) {
                log.warn("clients.yml 客户端 {} 加载失败: {}", cSafe(c2(o)), e.getMessage());
            }
        }
        log.info("clients.yml 加载完成: created={} updated={} unchanged={}", created, updated, unchanged);
    }

    private static boolean Bool(Object v, boolean dflt) {
        return v == null ? dflt : Boolean.parseBoolean(String.valueOf(v));
    }

    private static String cSafe(String s) {
        return s == null ? "?" : s;
    }

    private static String c2(Object o) {
        try {
            return String.valueOf(((Map<String, Object>) o).get("client-id"));
        } catch (Exception e) {
            return null;
        }
    }
}
