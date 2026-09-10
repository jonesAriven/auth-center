package com.marschat.authcenter.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

@Slf4j
@Configuration
public class DatabaseInitializer implements CommandLineRunner {

    private final JdbcTemplate jdbcTemplate;
    private final PasswordEncoder passwordEncoder;

    public DatabaseInitializer(JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder) {
        this.jdbcTemplate = jdbcTemplate;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        createTableIfNotExists("operation_log", """
            CREATE TABLE IF NOT EXISTS operation_log (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT COMMENT '用户ID',
                username VARCHAR(100) COMMENT '用户名',
                action VARCHAR(100) COMMENT '操作类型',
                resource_type VARCHAR(50) COMMENT '资源类型',
                resource_id BIGINT COMMENT '资源ID',
                detail TEXT COMMENT '操作详情',
                ip VARCHAR(50) COMMENT 'IP地址',
                user_agent VARCHAR(500) COMMENT '用户代理',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id),
                INDEX idx_action (action),
                INDEX idx_resource (resource_type, resource_id),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='操作日志表'
            """);

        createTableIfNotExists("api_token", """
            CREATE TABLE IF NOT EXISTS api_token (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT NOT NULL COMMENT '用户ID',
                name VARCHAR(100) COMMENT '令牌名称',
                token VARCHAR(255) NOT NULL COMMENT '令牌值',
                expires_at DATETIME COMMENT '过期时间',
                last_used_at DATETIME COMMENT '最后使用时间',
                status INT DEFAULT 1 COMMENT '状态 1-启用 0-禁用',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                deleted INT DEFAULT 0,
                UNIQUE INDEX uk_token (token),
                INDEX idx_user_id (user_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='API令牌表'
            """);

        createTableIfNotExists("jwt_blacklist", """
            CREATE TABLE IF NOT EXISTS jwt_blacklist (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                token VARCHAR(500) NOT NULL COMMENT 'JWT令牌',
                expires_at DATETIME NOT NULL COMMENT '过期时间',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_token (token(255)),
                INDEX idx_expires_at (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='JWT黑名单表'
            """);

        createTableIfNotExists("refresh_token", """
            CREATE TABLE IF NOT EXISTS refresh_token (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT NOT NULL COMMENT '用户ID',
                token VARCHAR(500) NOT NULL COMMENT '刷新令牌',
                expires_at DATETIME NOT NULL COMMENT '过期时间',
                revoked INT DEFAULT 0 COMMENT '是否撤销 0-否 1-是',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id),
                INDEX idx_token (token(255))
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='刷新令牌表'
            """);

        createTableIfNotExists("user", """
            CREATE TABLE IF NOT EXISTS user (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL COMMENT '用户名',
                password VARCHAR(255) NOT NULL COMMENT '密码',
                nickname VARCHAR(100) COMMENT '昵称',
                email VARCHAR(100) COMMENT '邮箱',
                avatar VARCHAR(500) COMMENT '头像',
                status INT DEFAULT 1 COMMENT '状态 1-启用 0-禁用',
                realm_id VARCHAR(50) DEFAULT 'kb' COMMENT '账号所属realm(账号池)',
                role VARCHAR(20) DEFAULT 'user' COMMENT '角色 admin/user',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                deleted INT DEFAULT 0,
                UNIQUE INDEX uk_username (username),
                INDEX idx_email (email),
                INDEX idx_realm (realm_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表'
            """);

        // 存量库补列（幂等：已存在则报错吞掉）
        addColumnIfNotExists("user", "realm_id",
                "ALTER TABLE user ADD COLUMN realm_id VARCHAR(50) DEFAULT 'kb' COMMENT '账号所属realm(账号池)'");
        addColumnIfNotExists("user", "role",
                "ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT 'user' COMMENT '角色 admin/user'");
        addColumnIfNotExists("oauth2_registered_client", "client_secret_expires_at",
                "ALTER TABLE oauth2_registered_client ADD COLUMN client_secret_expires_at TIMESTAMP DEFAULT NULL");

        // Spring Authorization Server JDBC 表（官方 schema）
        createTableIfNotExists("oauth2_registered_client", """
            CREATE TABLE IF NOT EXISTS oauth2_registered_client (
                id VARCHAR(100) PRIMARY KEY,
                client_id VARCHAR(100) NOT NULL,
                client_id_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                client_secret VARCHAR(200) DEFAULT NULL,
                client_secret_expires_at TIMESTAMP DEFAULT NULL,
                client_name VARCHAR(200) DEFAULT NULL,
                client_authentication_methods VARCHAR(1000) DEFAULT NULL,
                authorization_grant_types VARCHAR(1000) DEFAULT NULL,
                redirect_uris VARCHAR(1000) DEFAULT NULL,
                post_logout_redirect_uris VARCHAR(1000) DEFAULT NULL,
                scopes VARCHAR(1000) DEFAULT NULL,
                client_settings VARCHAR(2000) NOT NULL,
                token_settings VARCHAR(2000) NOT NULL,
                UNIQUE INDEX uk_client_id (client_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='OIDC客户端注册表'
            """);
        createTableIfNotExists("oauth2_authorization", """
            CREATE TABLE IF NOT EXISTS oauth2_authorization (
                id VARCHAR(100) PRIMARY KEY,
                registered_client_id VARCHAR(200) NOT NULL,
                principal_name VARCHAR(200) NOT NULL,
                authorization_grant_type VARCHAR(100) NOT NULL,
                authorized_scopes VARCHAR(1000) DEFAULT NULL,
                attributes TEXT DEFAULT NULL,
                state VARCHAR(500) DEFAULT NULL,
                authorization_code_value TEXT DEFAULT NULL,
                authorization_code_issued_at TIMESTAMP DEFAULT NULL,
                authorization_code_expires_at TIMESTAMP DEFAULT NULL,
                authorization_code_metadata TEXT DEFAULT NULL,
                access_token_value TEXT DEFAULT NULL,
                access_token_issued_at TIMESTAMP DEFAULT NULL,
                access_token_expires_at TIMESTAMP DEFAULT NULL,
                access_token_metadata TEXT DEFAULT NULL,
                access_token_type VARCHAR(100) DEFAULT NULL,
                access_token_scopes VARCHAR(1000) DEFAULT NULL,
                oidc_id_token_value TEXT DEFAULT NULL,
                oidc_id_token_issued_at TIMESTAMP DEFAULT NULL,
                oidc_id_token_expires_at TIMESTAMP DEFAULT NULL,
                oidc_id_token_metadata TEXT DEFAULT NULL,
                refresh_token_value TEXT DEFAULT NULL,
                refresh_token_issued_at TIMESTAMP DEFAULT NULL,
                refresh_token_expires_at TIMESTAMP DEFAULT NULL,
                refresh_token_metadata TEXT DEFAULT NULL,
                user_code_value TEXT DEFAULT NULL,
                user_code_issued_at TIMESTAMP DEFAULT NULL,
                user_code_expires_at TIMESTAMP DEFAULT NULL,
                user_code_metadata TEXT DEFAULT NULL,
                device_code_value TEXT DEFAULT NULL,
                device_code_issued_at TIMESTAMP DEFAULT NULL,
                device_code_expires_at TIMESTAMP DEFAULT NULL,
                device_code_metadata TEXT DEFAULT NULL,
                INDEX idx_registered_client_id (registered_client_id),
                INDEX idx_principal_name (principal_name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='OIDC授权记录表'
            """);
        createTableIfNotExists("oauth2_authorization_consent", """
            CREATE TABLE IF NOT EXISTS oauth2_authorization_consent (
                registered_client_id VARCHAR(200) NOT NULL,
                principal_name VARCHAR(200) NOT NULL,
                authorities VARCHAR(1000) NOT NULL,
                PRIMARY KEY (registered_client_id, principal_name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='OIDC授权同意表'
            """);

        seedOidcClient();
        ensureAdminRole();

        createTableIfNotExists("sys_error_log", """
            CREATE TABLE IF NOT EXISTS sys_error_log (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT COMMENT '用户ID',
                username VARCHAR(100) COMMENT '用户名',
                level VARCHAR(20) COMMENT '日志级别 error/warn/info',
                source VARCHAR(50) COMMENT '来源 frontend/backend',
                message TEXT COMMENT '错误信息',
                stack_trace TEXT COMMENT '堆栈信息',
                url VARCHAR(500) COMMENT '页面URL',
                ip VARCHAR(50) COMMENT 'IP地址',
                user_agent VARCHAR(500) COMMENT '用户代理',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id),
                INDEX idx_level (level),
                INDEX idx_source (source),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='系统错误日志表'
            """);

        createTableIfNotExists("sys_request_log", """
            CREATE TABLE IF NOT EXISTS sys_request_log (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                trace_id VARCHAR(64) COMMENT '链路追踪ID',
                user_id BIGINT COMMENT '用户ID',
                username VARCHAR(100) COMMENT '用户名',
                http_method VARCHAR(10) COMMENT 'HTTP方法',
                request_uri VARCHAR(500) COMMENT '请求URI',
                controller_method VARCHAR(200) COMMENT '控制器方法',
                request_args TEXT COMMENT '请求参数',
                response_result TEXT COMMENT '响应结果',
                cost_ms BIGINT COMMENT '耗时(毫秒)',
                status VARCHAR(20) COMMENT '状态 success/error/slow',
                exception TEXT COMMENT '异常信息',
                ip VARCHAR(50) COMMENT 'IP地址',
                user_agent VARCHAR(500) COMMENT '用户代理',
                service_name VARCHAR(50) COMMENT '服务名称',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_trace_id (trace_id),
                INDEX idx_user_id (user_id),
                INDEX idx_status (status),
                INDEX idx_created_at (created_at),
                INDEX idx_service (service_name, created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='请求日志表'
            """);

        log.info("认证服务数据库表初始化完成");
    }

    private void createTableIfNotExists(String tableName, String ddl) {
        try {
            jdbcTemplate.execute(ddl);
            log.debug("表 {} 已就绪", tableName);
        } catch (Exception e) {
            log.warn("创建表 {} 失败: {}", tableName, e.getMessage());
        }
    }

    /** 兜底引导：全库没有任何 admin 时，把 username=admin 的账号提升为 admin（幂等） */
    private void ensureAdminRole() {
        try {
            Integer adminCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM user WHERE role = 'admin' AND deleted = 0", Integer.class);
            if (adminCount == null || adminCount == 0) {
                jdbcTemplate.update(
                    "UPDATE user SET role = 'admin' WHERE username = 'admin' AND deleted = 0");
                log.info("已将内置 admin 账号引导为管理员角色");
            }
        } catch (Exception e) {
            log.warn("admin 角色引导失败: {}", e.getMessage());
        }
    }

    private void addColumnIfNotExists(String tableName, String columnName, String alterSql) {
        try {
            Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() " +
                "AND TABLE_NAME = ? AND COLUMN_NAME = ?", Integer.class, tableName, columnName);
            if (count == null || count == 0) {
                jdbcTemplate.execute(alterSql);
                log.info("表 {} 补列 {} 完成", tableName, columnName);
            }
        } catch (Exception e) {
            log.warn("表 {} 补列 {} 失败: {}", tableName, columnName, e.getMessage());
        }
    }

    /** 种子 OIDC 客户端（幂等，client_id 唯一索引兜底）；已存在时补齐回调白名单 */
    private void seedOidcClient() {
        java.util.List<String> requiredRedirects = java.util.List.of(
                "http://localhost:5173/auth/callback",
                "https://main.marschat.online/portal/auth/callback",
                "http://192.168.31.105:8095/portal/auth/callback");
        try {
            JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);
            RegisteredClient existing = repository.findByClientId("marschat-portal");
            if (existing == null) {
                RegisteredClient portal = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("marschat-portal")
                        .clientSecret(passwordEncoder.encode("portal-secret-2026"))
                        .clientName("MarsChat Portal")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUris(r -> r.addAll(requiredRedirects))
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                        .tokenSettings(org.springframework.security.oauth2.server.authorization.settings.TokenSettings.builder()
                                .accessTokenTimeToLive(java.time.Duration.ofMinutes(30))
                                .refreshTokenTimeToLive(java.time.Duration.ofDays(7))
                                .reuseRefreshTokens(false)
                                .build())
                        .build();
                repository.save(portal);
                log.info("种子 OIDC 客户端 marschat-portal 已就绪");
            } else if (!existing.getRedirectUris().containsAll(requiredRedirects)) {
                RegisteredClient updated = RegisteredClient.from(existing)
                        .redirectUris(r -> {
                            r.clear();
                            r.addAll(requiredRedirects);
                        })
                        .build();
                repository.save(updated);
                log.info("已更新 marschat-portal 回调白名单: {}", requiredRedirects);
            }
        seedKbwebClient(repository);
        seedKbopsClient(repository);
        seedInframonClient(repository);
            seedP2Clients(repository);
        } catch (Exception e) {
            log.warn("种子 OIDC 客户端失败: {}", e.getMessage());
        }
    }

    /**
     * P2 批量播种：activecode / memory（记忆提炼面板）/ tokenhub 三个 public client（PKCE）。
     * 回调地址按各应用部署 URL 预置，代理/后续接入若需调整走幂等补齐逻辑（containsAll 对比）。
     */
    private void seedP2Clients(JdbcRegisteredClientRepository repository) {
        // 回调用 .html 后缀：Spring Boot 静态资源映射要求带扩展名，无后缀路由 404
        seedPublicClient(repository, "marschat-activecode", "MarsChat ActiveCode (SPA)",
                java.util.List.of(
                        "https://tools.marschat.online/activecode/sso-callback.html",
                        "http://192.168.31.182:18080/activecode/sso-callback.html",
                        "http://192.168.31.105:18080/activecode/sso-callback.html"));
        seedPublicClient(repository, "marschat-memory", "MarsChat Memory Extract Panel",
                java.util.List.of(
                        "https://memory.marschat.online/sso-callback",
                        "http://192.168.31.105:8720/sso-callback"));
        // TokenHub 是开源项目 astaxie/TokenHub（Go+Next.js），原生支持 generic_oidc 身份源，
        // 无需改其代码——回调地址是它内置的 /api/admin/auth/oauth/callback
        seedPublicClient(repository, "marschat-tokenhub", "MarsChat TokenHub",
                java.util.List.of(
                        "https://tokenhub.marschat.online/api/admin/auth/oauth/callback",
                        "http://192.168.31.105:13000/api/admin/auth/oauth/callback"));
    }

    /** 通用 public client 播种（PKCE + rotation + 回调白名单幂等补齐），供 P2 批量与后续新应用复用 */
    private void seedPublicClient(JdbcRegisteredClientRepository repository,
                                  String clientId, String clientName,
                                  java.util.List<String> requiredRedirects) {
        try {
            RegisteredClient existing = repository.findByClientId(clientId);
            if (existing == null) {
                RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId(clientId)
                        .clientName(clientName)
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUris(r -> r.addAll(requiredRedirects))
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(false)
                                .requireProofKey(true)
                                .build())
                        .tokenSettings(org.springframework.security.oauth2.server.authorization.settings.TokenSettings.builder()
                                .accessTokenTimeToLive(java.time.Duration.ofMinutes(30))
                                .refreshTokenTimeToLive(java.time.Duration.ofDays(7))
                                .reuseRefreshTokens(false)
                                .build())
                        .build();
                repository.save(client);
                log.info("种子 OIDC 客户端 {}（public/PKCE）已就绪", clientId);
            } else if (!existing.getRedirectUris().containsAll(requiredRedirects)) {
                RegisteredClient updated = RegisteredClient.from(existing)
                        .redirectUris(r -> {
                            r.clear();
                            r.addAll(requiredRedirects);
                        })
                        .build();
                repository.save(updated);
                log.info("已更新 {} 回调白名单: {}", clientId, requiredRedirects);
            }
        } catch (Exception e) {
            log.warn("种子 OIDC 客户端 {} 失败: {}", clientId, e.getMessage());
        }
    }

    /**
     * 种子 infra-monitor 监控平台前端 SPA 专用 public client（PKCE，无 secret）。
     * 与 kb-web 同构：纯前端无法安全持有 client_secret，走 authorization_code + PKCE；
     * refresh_token 供 SSO 登录后静默续期。回调按 infra-monitor-web 的 base=/infra 动态生成。
     */
    private void seedInframonClient(JdbcRegisteredClientRepository repository) {
        java.util.List<String> requiredRedirects = java.util.List.of(
                "https://monitor.marschat.online/infra/sso-callback",
                "http://192.168.31.105/infra/sso-callback",
                "http://localhost:3002/infra/sso-callback");
        try {
            RegisteredClient existing = repository.findByClientId("marschat-inframon");
            if (existing == null) {
                RegisteredClient inframon = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("marschat-inframon")
                        .clientName("MarsChat Infra Monitor (SPA)")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUris(r -> r.addAll(requiredRedirects))
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(false)
                                .requireProofKey(true)
                                .build())
                        .tokenSettings(org.springframework.security.oauth2.server.authorization.settings.TokenSettings.builder()
                                .accessTokenTimeToLive(java.time.Duration.ofMinutes(30))
                                .refreshTokenTimeToLive(java.time.Duration.ofDays(7))
                                .reuseRefreshTokens(false)
                                .build())
                        .build();
                repository.save(inframon);
                log.info("种子 OIDC 客户端 marschat-inframon（public/PKCE）已就绪");
            } else if (!existing.getRedirectUris().containsAll(requiredRedirects)) {
                RegisteredClient updated = RegisteredClient.from(existing)
                        .redirectUris(r -> {
                            r.clear();
                            r.addAll(requiredRedirects);
                        })
                        .build();
                repository.save(updated);
                log.info("已更新 marschat-inframon 回调白名单: {}", requiredRedirects);
            }
        } catch (Exception e) {
            log.warn("种子 OIDC 客户端 marschat-inframon 失败: {}", e.getMessage());
        }
    }

    /**
     * 种子 kb-ops 运维平台前端 SPA 专用 public client（PKCE，无 secret）。
     * 与 kb-web 同构：纯前端无法安全持有 client_secret，走 authorization_code + PKCE。
     */
    private void seedKbopsClient(JdbcRegisteredClientRepository repository) {
        java.util.List<String> requiredRedirects = java.util.List.of(
                "http://localhost:3001/ops/sso-callback",
                "https://kb.marschat.online/ops/sso-callback",
                "http://192.168.31.105/ops/sso-callback");
        try {
            RegisteredClient existing = repository.findByClientId("marschat-kbops");
            if (existing == null) {
                RegisteredClient kbops = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("marschat-kbops")
                        .clientName("MarsChat KB Ops (SPA)")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUris(r -> r.addAll(requiredRedirects))
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(false)
                                .requireProofKey(true)
                                .build())
                        .tokenSettings(org.springframework.security.oauth2.server.authorization.settings.TokenSettings.builder()
                                .accessTokenTimeToLive(java.time.Duration.ofMinutes(30))
                                .refreshTokenTimeToLive(java.time.Duration.ofDays(7))
                                .reuseRefreshTokens(false)
                                .build())
                        .build();
                repository.save(kbops);
                log.info("种子 OIDC 客户端 marschat-kbops（public/PKCE）已就绪");
            } else if (!existing.getRedirectUris().containsAll(requiredRedirects)) {
                RegisteredClient updated = RegisteredClient.from(existing)
                        .redirectUris(r -> {
                            r.clear();
                            r.addAll(requiredRedirects);
                        })
                        .build();
                repository.save(updated);
                log.info("已更新 marschat-kbops 回调白名单: {}", requiredRedirects);
            }
        } catch (Exception e) {
            log.warn("种子 OIDC 客户端 marschat-kbops 失败: {}", e.getMessage());
        }
    }

    /**
     * 种子 kb-web 前端 SPA 专用 public client（PKCE，无 secret）。
     * 纯前端应用无法安全持有 client_secret，走 authorization_code + PKCE；refresh_token 供静默续期。
     */
    private void seedKbwebClient(JdbcRegisteredClientRepository repository) {
        java.util.List<String> requiredRedirects = java.util.List.of(
                "http://localhost:5173/kb/sso-callback",
                "https://kb.marschat.online/kb/sso-callback",
                "http://192.168.31.105/kb/sso-callback");
        try {
            RegisteredClient existing = repository.findByClientId("marschat-kbweb");
            if (existing == null) {
                RegisteredClient kbweb = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("marschat-kbweb")
                        .clientName("MarsChat KB Web (SPA)")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUris(r -> r.addAll(requiredRedirects))
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(false)
                                .requireProofKey(true)
                                .build())
                        .tokenSettings(org.springframework.security.oauth2.server.authorization.settings.TokenSettings.builder()
                                .accessTokenTimeToLive(java.time.Duration.ofMinutes(30))
                                .refreshTokenTimeToLive(java.time.Duration.ofDays(7))
                                .reuseRefreshTokens(false)
                                .build())
                        .build();
                repository.save(kbweb);
                log.info("种子 OIDC 客户端 marschat-kbweb（public/PKCE）已就绪");
            } else if (!existing.getRedirectUris().containsAll(requiredRedirects)) {
                RegisteredClient updated = RegisteredClient.from(existing)
                        .redirectUris(r -> {
                            r.clear();
                            r.addAll(requiredRedirects);
                        })
                        .build();
                repository.save(updated);
                log.info("已更新 marschat-kbweb 回调白名单: {}", requiredRedirects);
            }
        } catch (Exception e) {
            log.warn("种子 OIDC 客户端 marschat-kbweb 失败: {}", e.getMessage());
        }
    }
}
