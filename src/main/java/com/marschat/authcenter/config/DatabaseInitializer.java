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
                username VARCHAR(64) NOT NULL COMMENT '用户名',
                password VARCHAR(255) NOT NULL COMMENT '密码',
                nickname VARCHAR(100) COMMENT '昵称',
                email VARCHAR(128) COMMENT '邮箱',
                phone VARCHAR(20) COMMENT '手机号',
                wechat_openid VARCHAR(64) COMMENT '微信openid',
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

        // 新增表：用户身份表（邮箱/手机/微信唯一性下沉到 DB 层，UNIQUE(provider,identifier) 为唯一事实）
        createTableIfNotExists("user_identity", """
            CREATE TABLE IF NOT EXISTS user_identity (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT NOT NULL COMMENT '用户ID',
                provider VARCHAR(32) NOT NULL COMMENT '身份提供方 email/phone/wechat',
                identifier VARCHAR(128) NOT NULL COMMENT '唯一标识(与email(128)对齐避免索引截断)',
                verified TINYINT DEFAULT 0 COMMENT '是否已验证 0-否 1-是',
                is_primary TINYINT DEFAULT 0 COMMENT '是否主身份 0-否 1-是',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE INDEX uk_provider_identifier (provider, identifier),
                INDEX idx_user_id (user_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户身份表'
            """);

        // 新增表：用户凭证表（password 暂不迁移，本表仅建结构，user.password 继续生效）
        createTableIfNotExists("user_credential", """
            CREATE TABLE IF NOT EXISTS user_credential (
                user_id BIGINT NOT NULL COMMENT '用户ID',
                type VARCHAR(32) NOT NULL COMMENT '凭证类型 password/oauth',
                secret VARCHAR(255) COMMENT '凭证密钥(加密存储)',
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE INDEX uk_user_type (user_id, type)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户凭证表'
            """);

        // ============ Phase 2 · RBAC 六表（unified-auth 方案 §3.2 权威 schema） ============
        createTableIfNotExists("sys_role", """
            CREATE TABLE IF NOT EXISTS sys_role (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                scope VARCHAR(16) NOT NULL DEFAULT 'platform' COMMENT 'platform=平台角色 | client=应用角色',
                client_id VARCHAR(64) NULL COMMENT 'client 级角色归属的应用（platform 级为 NULL）',
                code VARCHAR(64) NOT NULL COMMENT '角色标识',
                name VARCHAR(64) NOT NULL COMMENT '显示名',
                description VARCHAR(255) NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE INDEX uk_scope_client_code (scope, client_id, code)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='角色表（平台/应用双层）'
            """);
        createTableIfNotExists("sys_permission", """
            CREATE TABLE IF NOT EXISTS sys_permission (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                client_id VARCHAR(64) NOT NULL COMMENT '归属应用',
                type VARCHAR(16) NOT NULL COMMENT 'menu|api|action（权限粒度=菜单+接口两级）',
                code VARCHAR(128) NOT NULL COMMENT '权限点标识，如 dashboard / deployment:create',
                name VARCHAR(128) NOT NULL,
                parent_id BIGINT NULL COMMENT '菜单树自关联',
                sort INT DEFAULT 0,
                status TINYINT DEFAULT 1 COMMENT '1=有效 0=已失效（上报全量覆盖后消失的条目）',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE INDEX uk_client_type_code (client_id, type, code),
                INDEX idx_parent (parent_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='权限点表（菜单/接口）'
            """);
        createTableIfNotExists("sys_role_permission", """
            CREATE TABLE IF NOT EXISTS sys_role_permission (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                role_id BIGINT NOT NULL,
                permission_id BIGINT NOT NULL,
                UNIQUE INDEX uk_role_perm (role_id, permission_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='角色-权限点绑定'
            """);
        createTableIfNotExists("sys_user_menu_override", """
            CREATE TABLE IF NOT EXISTS sys_user_menu_override (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT NOT NULL,
                permission_id BIGINT NOT NULL,
                action VARCHAR(8) DEFAULT 'deny' COMMENT 'deny=从角色权限中扣除（白名单减法，只能减不能加）',
                granted_by BIGINT NULL COMMENT '授权人（审计）',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE INDEX uk_user_perm (user_id, permission_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户级菜单覆盖（R9：角色默认+用户减法）'
            """);
        createTableIfNotExists("sys_user_role", """
            CREATE TABLE IF NOT EXISTS sys_user_role (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT NOT NULL,
                role_id BIGINT NOT NULL,
                client_id VARCHAR(64) NULL COMMENT '授权作用域（client 级记录应用；platform 级 NULL）',
                granted_by BIGINT NULL COMMENT '授权人（审计）',
                granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE INDEX uk_user_role_scope (user_id, role_id, client_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户-角色绑定（谁在什么系统是什么角色）'
            """);
        createTableIfNotExists("sys_role_composite", """
            CREATE TABLE IF NOT EXISTS sys_role_composite (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                parent_role_id BIGINT NOT NULL COMMENT '父角色（如应用管理员）',
                child_role_id BIGINT NOT NULL COMMENT '子角色（如编辑者）',
                UNIQUE INDEX uk_parent_child (parent_role_id, child_role_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='角色继承（父角色自动含子角色权限）'
            """);
        createTableIfNotExists("sys_app_client", """
            CREATE TABLE IF NOT EXISTS sys_app_client (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                client_id VARCHAR(64) NOT NULL,
                name VARCHAR(128) NOT NULL,
                status TINYINT DEFAULT 1 COMMENT '1=启用',
                menu_registry_json MEDIUMTEXT NULL COMMENT '应用最近一次上报的菜单树原文（全量覆盖）',
                last_sync_at DATETIME NULL COMMENT '最近上报时间',
                client_secret VARCHAR(128) NULL COMMENT '应用上报凭据(X-Client-Secret)；NULL=未启用internal上报',
                UNIQUE INDEX uk_client (client_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='应用注册表（菜单上报元数据）'
            """);

        // 存量库补列（幂等：information_schema 探明后执行，已存在则跳过）
        addColumnIfNotExists("user", "realm_id",
                "ALTER TABLE user ADD COLUMN realm_id VARCHAR(50) DEFAULT 'kb' COMMENT '账号所属realm(账号池)'");
        addColumnIfNotExists("user", "role",
                "ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT 'user' COMMENT '角色 admin/user'");
        addColumnIfNotExists("user", "phone",
                "ALTER TABLE user ADD COLUMN phone VARCHAR(20) COMMENT '手机号'");
        addColumnIfNotExists("user", "wechat_openid",
                "ALTER TABLE user ADD COLUMN wechat_openid VARCHAR(64) COMMENT '微信openid'");
        // 列长对齐线上（存量库已为 64/128 时会被 information_schema 探明后跳过，仅修正老环境旧建表）
        alterColumnTypeIfNeeded("user", "username", "varchar(64)",
                "ALTER TABLE user MODIFY COLUMN username VARCHAR(64) NOT NULL COMMENT '用户名'");
        alterColumnTypeIfNeeded("user", "email", "varchar(128)",
                "ALTER TABLE user MODIFY COLUMN email VARCHAR(128) COMMENT '邮箱'");
        addColumnIfNotExists("oauth2_registered_client", "client_secret_expires_at",
                "ALTER TABLE oauth2_registered_client ADD COLUMN client_secret_expires_at TIMESTAMP DEFAULT NULL");
        // Phase 4 P-B：应用菜单上报凭据（X-Client-Secret）；NULL=该应用未启用 internal 上报通道
        addColumnIfNotExists("sys_app_client", "client_secret",
                "ALTER TABLE sys_app_client ADD COLUMN client_secret VARCHAR(128) NULL COMMENT '应用上报凭据(X-Client-Secret)；NULL=未启用internal上报'");

        // 存量数据迁移：user.email/phone/wechat_openid -> user_identity（幂等，可重复执行）
        migrateUserIdentities();

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

        // Phase 3 配置化（R5=L1）：OIDC 客户端种子改由 ClientsYmlLoader 读 classpath clients.yml
        // （apps-registry.yml 派生），原 seedOidcClient + 5 个 seedXxx 硬编码方法已删除
        ensureAdminRole();
        seedRbacBase();

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

    /**
     * 兜底引导：全库没有任何 admin/superadmin 时，把 username=admin 的账号提升为 admin（幂等）。
     * ⚠️ 2026-09-13 事故修正：adminCount 原只统计 role='admin'——手动把 admin 升为 superadmin
     * 后全库"无 admin"，本引导会把 superadmin **覆盖回 admin**（实锤发生过），随后删除保护
     * 失效被真删。修正=统计口径含 superadmin，且 role 已是 superadmin 时绝不降级。
     */
    private void ensureAdminRole() {
        try {
            Integer adminCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM user WHERE role IN ('admin', 'superadmin') AND deleted = 0", Integer.class);
            if (adminCount == null || adminCount == 0) {
                jdbcTemplate.update(
                    "UPDATE user SET role = 'admin' WHERE username = 'admin' AND deleted = 0 "
                    + "AND role NOT IN ('superadmin')");
                log.info("已将内置 admin 账号引导为管理员角色");
            }
        } catch (Exception e) {
            log.warn("admin 角色引导失败: {}", e.getMessage());
        }
    }

    /**
     * RBAC 基础种子（幂等，Phase 2）：
     * ① 平台角色 admin/user（scope=platform，与既有 user.role 字段同语义）；
     * ② 所有活跃 admin 绑定平台 admin 角色；活跃 user 绑定平台 user 角色；
     * ③ sys_app_client 从 oauth2_registered_client 补齐应用注册条目。
     * ⚠️ R10 默认策略：未配置权限点的应用 = 行为不变——本种子**不**建任何 sys_permission，
     * 权限点由 Phase 4 菜单上报 / 接口注册产生。
     */
    private void seedRbacBase() {
        try {
            jdbcTemplate.update("""
                INSERT INTO sys_role (scope, client_id, code, name, description)
                SELECT 'platform', NULL, 'admin', '平台管理员', '全平台管理权限（含各应用管理接口）'
                WHERE NOT EXISTS (SELECT 1 FROM sys_role WHERE scope='platform' AND code='admin')
                """);
            jdbcTemplate.update("""
                INSERT INTO sys_role (scope, client_id, code, name, description)
                SELECT 'platform', NULL, 'user', '普通用户', '平台基础权限'
                WHERE NOT EXISTS (SELECT 1 FROM sys_role WHERE scope='platform' AND code='user')
                """);
            jdbcTemplate.update("""
                INSERT INTO sys_user_role (user_id, role_id, client_id, granted_by)
                SELECT u.id, r.id, NULL, NULL FROM user u
                JOIN sys_role r ON r.scope='platform' AND r.code='admin'
                WHERE u.role='admin' AND u.deleted=0
                  AND NOT EXISTS (SELECT 1 FROM sys_user_role ur WHERE ur.user_id=u.id AND ur.role_id=r.id)
                """);
            jdbcTemplate.update("""
                INSERT INTO sys_user_role (user_id, role_id, client_id, granted_by)
                SELECT u.id, r.id, NULL, NULL FROM user u
                JOIN sys_role r ON r.scope='platform' AND r.code='user'
                WHERE u.role<>'admin' AND u.deleted=0
                  AND NOT EXISTS (SELECT 1 FROM sys_user_role ur WHERE ur.user_id=u.id AND ur.role_id=r.id)
                """);
            jdbcTemplate.update("""
                INSERT INTO sys_app_client (client_id, name, status)
                SELECT c.client_id, COALESCE(c.client_name, c.client_id), 1
                FROM oauth2_registered_client c
                WHERE NOT EXISTS (SELECT 1 FROM sys_app_client a WHERE a.client_id=c.client_id)
                """);
            log.info("RBAC 基础种子完成（平台角色/绑定/应用注册表）");
        } catch (Exception e) {
            log.warn("RBAC 种子失败: {}", e.getMessage());
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

    /** 列长对齐：仅当 information_schema 中实际类型与预期不符时才 ALTER（幂等，存量已对齐库自动跳过） */
    private void alterColumnTypeIfNeeded(String tableName, String columnName, String expectedType, String alterSql) {
        try {
            String actual = jdbcTemplate.queryForObject(
                "SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() " +
                "AND TABLE_NAME = ? AND COLUMN_NAME = ?", String.class, tableName, columnName);
            if (actual != null && !actual.equalsIgnoreCase(expectedType)) {
                jdbcTemplate.execute(alterSql);
                log.info("表 {} 列 {} 类型由 {} 调整为 {}", tableName, columnName, actual, expectedType);
            }
        } catch (Exception e) {
            log.warn("表 {} 列 {} 类型调整失败: {}", tableName, columnName, e.getMessage());
        }
    }

    /**
     * 存量迁移：把 user 表的 email/phone/wechat_openid 写入 user_identity。
     * 幂等保证：① application 每次启动都会跑 run()，故逐行先查 user_identity 是否已存在 (provider,identifier)；
     *          ② UNIQUE(provider,identifier) 兜底，即使并发也不会产生重复行；③ 跳过 NULL 与空串。
     * verified 统一置 0：老数据由早期注册流程写入，系统从未发起过验证回执，无证据证明确已验证，置 1 会虚假断言。
     * is_primary 置 1：这些是用户当前唯一且主用的联系方式。
     */
    private void migrateUserIdentities() {
        try {
            // provider -> 源列名
            String[][] specs = {
                {"email", "email"},
                {"phone", "phone"},
                {"wechat", "wechat_openid"}
            };
            for (String[] spec : specs) {
                String provider = spec[0];
                String column = spec[1];
                java.util.List<Long> userIds = jdbcTemplate.query(
                        "SELECT id FROM user WHERE deleted = 0 AND " + column + " IS NOT NULL AND " + column + " <> ''",
                        (rs, i) -> rs.getLong("id"));
                for (Long userId : userIds) {
                    String identifier = jdbcTemplate.queryForObject(
                            "SELECT " + column + " FROM user WHERE id = ?", String.class, userId);
                    if (identifier == null || identifier.isEmpty()) {
                        continue;
                    }
                    Integer exists = jdbcTemplate.queryForObject(
                            "SELECT COUNT(*) FROM user_identity WHERE provider = ? AND identifier = ?",
                            Integer.class, provider, identifier);
                    if (exists != null && exists > 0) {
                        continue;
                    }
                    jdbcTemplate.update(
                            "INSERT INTO user_identity (user_id, provider, identifier, verified, is_primary, created_at) "
                                    + "VALUES (?, ?, ?, 0, 1, NOW())",
                            userId, provider, identifier);
                }
            }
            log.info("user_identity 存量迁移完成（幂等，UNIQUE(provider,identifier) 兜底）");
        } catch (Exception e) {
            log.warn("user_identity 存量迁移失败: {}", e.getMessage());
        }
    }

}
