package com.marschat.authcenter.service;

import com.marschat.authcenter.config.AuthzProperties;
import com.marschat.authcenter.security.RoleCodes;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * RBAC 权限计算（Phase 2 底座）。
 *
 * <p>三层模型（unified-auth 方案 §3.2）：平台角色 / 应用角色 / 权限点（menu|api 两级粒度）。
 * 计算口径：
 * <pre>
 *   平台角色 = user.role（存量字段） ∪ sys_user_role(platform 级绑定)
 *   应用角色 = sys_user_role(client 级绑定) → sys_role_composite 递归展开子角色
 *   权限点   = 上述角色 → sys_role_permission → sys_permission(status=1, client=本应用)
 *   configured = 该应用是否存在至少一条「角色→权限」绑定（sys_role_permission ⋈ sys_permission）
 * </pre>
 * <b>R10 默认策略</b>：configured=false 时调用方（前端守卫 / 拦截器）按「行为不变」放行，
 * 保证存量应用零波及。
 * <p>⚠️「已上报菜单定义」≠「已配置授权」：菜单上报只往 sys_permission 写权限点定义（0 条
 * 角色绑定），若以「有权限点记录」判 configured，会让刚接入上报的应用对非超管立即锁死。
 * 故 configured 以「真的存在角色→权限绑定」为准——上报与授权解耦，漏配授权不锁死；
 * 一旦配了第一条绑定即刻接管过滤。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PermissionService {

    private final JdbcTemplate jdbcTemplate;

    /** 操作审计（Phase 8：应用级角色绑定/移出必须留痕） */
    private final OperationLogService operationLogService;

    /** 授权默认策略（strict=默认最小权限 / legacy=默认全给）。 */
    private final AuthzPolicyService authzPolicy;

    /** 单次 composite 展开深度上限（防环）。 */
    private static final int MAX_DEPTH = 8;

    /**
     * 「应用管理员」判定所用的权限点（{@code sys_permission} 内 {@code type=api, code=admin:write}）。
     *
     * <p>全码形式为 {@code {clientId}:api:admin:write} —— 与 cosmic BFF
     * {@code require_permission("api:admin:write", min_role="admin")} 是**同一权限点**，
     * 只是此处补上了 client 前缀（{@code computeForUser} 的下发口径）。
     * 同一权限点两处消费（业务写接口的 {@code PermissionAuthzFilter} + 管理面的
     * {@code AppAuthzEvaluator}），是设计一致的，不是重复（见设计规格 §1.6）。
     */
    private static final String APP_ADMIN_PERM_SUFFIX = ":api:admin:write";

    public Map<String, Object> computeForUser(long userId, String clientId) {
        Set<String> platformRoles = platformRoles(userId);
        Set<String> clientRoleCodes = clientRoleCodes(userId, clientId);

        Set<String> roleCodes = new LinkedHashSet<>(platformRoles);
        roleCodes.addAll(clientRoleCodes);
        // ⚠️ 作用域分离：平台角色 code 只在 platform 作用域解析，应用角色 code 只在本应用
        //    解析。改造前是「code 全域匹配」，client 侧建一个同名 admin 角色即全域提权。
        Set<Long> roleIds = new HashSet<>();
        roleIds.addAll(roleIdsByCodes(platformRoles, "platform", null));
        roleIds.addAll(roleIdsByCodes(clientRoleCodes, "client", clientId));
        expandComposites(roleIds, 0);
        roleCodes.addAll(roleCodesByIds(roleIds));

        Set<String> permissions = permissionsFor(clientId, roleIds);
        boolean configured = permissionConfigured(clientId);
        // strict：public 菜单 = 「已登录即可见」，与角色绑定无关地兜底补上，
        // 避免「应用尚未给任何角色授权」时登录后一片空白。
        if (authzPolicy.isStrict(clientId)) {
            permissions.addAll(authzPolicy.publicMenuCodes(clientId));
        }
        // R9 用户级减法：角色默认权限 − 用户 override（deny）——只减不加
        permissions.removeAll(deniedMenuCodes(userId, clientId));

        Map<String, Object> out = new HashMap<>();
        out.put("client", clientId);
        out.put("platformRoles", List.copyOf(platformRoles));
        out.put("roles", List.copyOf(roleCodes));
        out.put("permissions", List.copyOf(permissions));
        out.put("configured", configured);
        out.put("authzMode", authzPolicy.isStrict(clientId)
                ? AuthzProperties.MODE_STRICT : AuthzProperties.MODE_LEGACY);
        return out;
    }

    /**
     * 判断用户是否为某应用的「应用管理员」（三层权限 API · Membership 层判据）。
     *
     * <p><b>口径 A（推荐、复用已有权限点）</b>：该用户在该 client 下持有
     * {@code api:admin:write} 权限点。原料复用 {@link #computeForUser(long, String)}
     * 返回的 {@code permissions} 集合（全码形式 {@code clientId:type:code}，
     * 本判据即 {@code clientId:api:admin:write}）。
     *
     * <p><b>fail-closed（管理面）</b>：任何异常一律返回 {@code false} 并记 WARN ——
     * 判定失败时**不授予**应用管理权限（宁可拒绝）。本方法只在 {@code @PreAuthorize}
     * 的 {@code /admin/**} 鉴权面被调用，**不在** {@code /auth/login}、{@code /auth/refresh}、
     * {@code /auth/mail-login} 登录主链路上：auth-center 是 SSO 枢纽，登录 500 = 全站不可用，
     * 故此判定**绝不**向登录链路引入新的硬依赖。
     *
     * <p>注意与 {@code computeForUser} 一致：本方法为只读查询，可能触发 DB 访问；
     * 即使 DB/Redis 不可用，也只影响管理面判定的结果（拒绝），不影响登录与刷新。
     *
     * @param userId   调用者用户 id
     * @param clientId 目标应用标识（须来自 URL path，见 {@code AdminClientMemberController}）
     * @return true = 该用户是本应用的「应用管理员」
     */
    public boolean isAppAdmin(long userId, String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return false;
        }
        try {
            Map<String, Object> computed = computeForUser(userId, clientId);
            Object perms = computed == null ? null : computed.get("permissions");
            if (!(perms instanceof Collection<?> coll)) {
                return false;
            }
            String adminFullCode = clientId + APP_ADMIN_PERM_SUFFIX;
            for (Object p : coll) {
                if (adminFullCode.equals(String.valueOf(p))) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            log.warn("应用管理员判定失败（fail-closed）: user={} client={} err={}",
                    userId, clientId, e.getMessage());
            return false;
        }
    }

    /** 用户在某应用的 menu 覆盖排除集（下发的全码形式）。 */
    private Set<String> deniedMenuCodes(long userId, String clientId) {
        try {
            List<String> rows = jdbcTemplate.query(
                    "SELECT p.type, p.code FROM sys_user_menu_override o "
                    + "JOIN sys_permission p ON p.id = o.permission_id "
                    + "WHERE o.user_id=? AND o.action='deny' AND p.client_id=? AND p.type='menu'",
                    (rs, i) -> rs.getString(1) + ":" + rs.getString(2), userId, clientId);
            return rows.stream().map(r -> clientId + ":" + r).collect(Collectors.toSet());
        } catch (Exception e) {
            log.debug("读用户菜单覆盖失败: {}", e.getMessage());
            return new HashSet<>();
        }
    }

    /** 平台角色：存量 user.role 字段 + sys_user_role 的 platform 级绑定。 */
    private Set<String> platformRoles(long userId) {
        Set<String> out = new HashSet<>();
        try {
            out.addAll(jdbcTemplate.queryForList(
                    "SELECT role FROM user WHERE id=? AND deleted=0", String.class, userId));
            out.addAll(jdbcTemplate.queryForList("""
                    SELECT r.code FROM sys_user_role ur
                    JOIN sys_role r ON r.id = ur.role_id
                    WHERE ur.user_id=? AND ur.client_id IS NULL
                    """, String.class, userId));
        } catch (Exception e) {
            log.warn("读取平台角色失败: {}", e.getMessage());
        }
        return out;
    }

    /** 应用角色 code：sys_user_role 的 client 级绑定。 */
    private Set<String> clientRoleCodes(long userId, String clientId) {
        try {
            return new HashSet<>(jdbcTemplate.queryForList("""
                    SELECT r.code FROM sys_user_role ur
                    JOIN sys_role r ON r.id = ur.role_id
                    WHERE ur.user_id=? AND ur.client_id=?
                    """, String.class, userId, clientId));
        } catch (Exception e) {
            log.debug("读取应用角色失败: {}", e.getMessage());
            return new HashSet<>();
        }
    }

    /**
     * 角色 code → id（<b>带作用域</b>）。
     *
     * <p>⚠️ 改造前这里是「按 code 全域匹配」：{@code scope='platform' OR (scope='client' AND client_id=?)}
     * 一把梭，意味着任一应用只要建一个 code 与平台角色同名的角色（如 {@code admin}），
     * 就能让持有该平台角色的用户在全域命中它 —— 改一个字段即提权，且
     * {@code sys_user_role} 里查不到痕迹，审计不可信。
     * <p>改造后调用方必须显式声明作用域，两条路径互不串味。
     *
     * @param codes     角色 code 集合
     * @param scope     {@code platform}（clientId 传 null）或 {@code client}（clientId 必填）
     * @param clientId  scope=client 时的应用标识
     */
    public Set<Long> roleIdsByCodes(Set<String> codes, String scope, String clientId) {
        Set<Long> out = new HashSet<>();
        if (codes == null || codes.isEmpty() || scope == null) {
            return out;
        }
        boolean platform = "platform".equals(scope);
        if (!platform && !"client".equals(scope)) {
            log.warn("非法角色作用域: {}（只接受 platform|client）", scope);
            return out;
        }
        String placeholders = String.join(",", java.util.Collections.nCopies(codes.size(), "?"));
        String sql;
        Object[] params;
        if (platform) {
            sql = ("SELECT DISTINCT r.id FROM sys_role r "
                    + "WHERE r.code IN (%s) AND r.scope='platform' AND r.client_id IS NULL")
                    .formatted(placeholders);
            params = codes.toArray();
        } else {
            sql = ("SELECT DISTINCT r.id FROM sys_role r "
                    + "WHERE r.code IN (%s) AND r.scope='client' AND r.client_id=?")
                    .formatted(placeholders);
            params = Stream.concat(codes.stream(), Stream.of(clientId)).toArray();
        }
        try {
            out.addAll(jdbcTemplate.queryForList(sql, Long.class, params));
        } catch (Exception e) {
            log.debug("角色 id 解析失败(scope={}): {}", scope, e.getMessage());
        }
        return out;
    }

    /** composite 递归展开：父角色 ⇒ 自动获得子角色。 */
    private void expandComposites(Set<Long> roleIds, int depth) {
        if (roleIds.isEmpty() || depth >= MAX_DEPTH) {
            return;
        }
        try {
            String placeholders = String.join(",", java.util.Collections.nCopies(roleIds.size(), "?"));
            List<Long> children = jdbcTemplate.queryForList(
                    "SELECT child_role_id FROM sys_role_composite WHERE parent_role_id IN (%s)"
                            .formatted(placeholders), Long.class, roleIds.toArray());
            if (roleIds.addAll(children)) {
                expandComposites(roleIds, depth + 1);
            }
        } catch (Exception e) {
            log.debug("composite 展开失败: {}", e.getMessage());
        }
    }

    private Set<String> roleCodesByIds(Set<Long> roleIds) {
        Set<String> out = new HashSet<>();
        if (roleIds.isEmpty()) {
            return out;
        }
        String placeholders = String.join(",", java.util.Collections.nCopies(roleIds.size(), "?"));
        try {
            out.addAll(jdbcTemplate.queryForList(
                    "SELECT code FROM sys_role WHERE id IN (%s)".formatted(placeholders),
                    String.class, roleIds.toArray()));
        } catch (Exception e) {
            log.debug("role code 回填失败: {}", e.getMessage());
        }
        return out;
    }

    /** 权限点：角色 → sys_role_permission → 本应用的有效权限点，code 规范 client:type:code。 */
    private Set<String> permissionsFor(String clientId, Set<Long> roleIds) {
        Set<String> out = new HashSet<>();
        if (roleIds.isEmpty()) {
            return out;
        }
        String placeholders = String.join(",", java.util.Collections.nCopies(roleIds.size(), "?"));
        Object[] params = Stream.concat(roleIds.stream(), Stream.of(clientId)).toArray();
        try {
            List<String> rows = jdbcTemplate.query(
                    """
                    SELECT DISTINCT p.type, p.code FROM sys_role_permission rp
                    JOIN sys_permission p ON p.id = rp.permission_id
                    WHERE rp.role_id IN (%s) AND p.client_id=? AND p.status=1
                    """.formatted(placeholders),
                    (rs, i) -> rs.getString(1) + ":" + rs.getString(2),
                    params);
            rows.forEach(row -> out.add(clientId + ":" + row));
        } catch (Exception e) {
            log.debug("权限点计算失败: {}", e.getMessage());
        }
        return out;
    }

    /**
     * 该应用是否「已配置授权」。
     *
     * <p>⚠️ 判据是「有角色绑定」而非「有权限点记录」——菜单上报只写 sys_permission 定义
     * （0 条角色绑定），若以「有记录」判定，刚接入上报的应用会对非超管立即过滤锁死
     * （「已上报菜单定义」≠「已配置授权」）。解耦后：漏配授权不锁死，配了第一条绑定即接管。
     *
     * <h3>strict 模式：与「是否全量绑定」彻底解耦</h3>
     * 改造前为了让 configured 变 true，把应用<b>全部 menu</b> 绑给平台 user 角色 —— 这就是
     * 「默认全给」的病根。strict 下改为：
     * <pre>
     *   configured = 有任意角色-权限绑定  OR  存在 public 菜单
     * </pre>
     * 即：应用只要声明了「已登录即可见」的 public 菜单、管理员做过任何一条授权、
     * 或该应用上报过任何权限点定义，过滤机制就接管（前端守卫照常工作），
     * <b>不再需要靠全量绑定去刷 true</b>。
     * <p>第三项（有权限点定义）是 fail-open 的封堵：若某应用的绑定全在默认角色上、
     * 被 strict 收敛摘空，而它又没声明 public 菜单，此时若 configured=false，
     * 前端 fail-open 会让所有人看到全部菜单 —— 比收敛前更糟。故只要有定义即接管。
     */
    private boolean permissionConfigured(String clientId) {
        if (authzPolicy.isStrict(clientId)) {
            return hasAnyBinding(clientId)
                    || authzPolicy.hasPublicMenu(clientId)
                    || authzPolicy.hasAnyPermission(clientId);
        }
        try {
            Integer n = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM sys_role_permission rp JOIN sys_permission p ON p.id=rp.permission_id WHERE p.client_id=?",
                    Integer.class, clientId);
            return n != null && n > 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 菜单上报（全量覆盖语义，Phase 4 上报链路的落库侧）。
     *
     * <p>应用上报 menu-registry.yml 原文；中心解析后 upsert {@code sys_permission(type=menu)}，
     * 上报中不存在的既有菜单条目标记 status=0（识别"已删除的菜单"），原文存
     * {@code sys_app_client.menu_registry_json}。返回 {upserted, retired} 计数。
     *
     * <p>树结构支持 {@code children} 嵌套（推荐，分组节点含子项）与扁平 {@code parent} 字段
     * （兼容既有上报方）；两者并存时树结构优先。§18.10 实测：旧实现只读顶层、children 子项全丢。
     *
     * <p>Phase 4 扩展（api 粒度）：yml 支持 {@code apis:} 平铺段（key/title），
     * 注册为 {@code type=api} 权限点（@RequirePermission("api:<key>") 消费）；
     * retired 全量覆盖覆盖 menu+api 两类。
     */
    @SuppressWarnings("unchecked")
    public Map<String, Integer> reportMenus(String clientId, String menusYaml) {
        org.yaml.snakeyaml.Yaml yaml = new org.yaml.snakeyaml.Yaml();
        Object root = yaml.load(menusYaml);
        List<Map<String, Object>> menus = new ArrayList<>();
        List<Map<String, Object>> apis = new ArrayList<>();
        if (root instanceof Map<?, ?> m) {
            if (m.get("menus") instanceof List<?> l) {
                for (Object o : l) {
                    if (o instanceof Map<?, ?> item) {
                        menus.add((Map<String, Object>) item);
                    }
                }
            }
            if (m.get("apis") instanceof List<?> l) {
                for (Object o : l) {
                    if (o instanceof Map<?, ?> item) {
                        apis.add((Map<String, Object>) item);
                    }
                }
            }
        }
        // collectedKeys 形如 "menu:hosts" / "api:hosts:create"（type:code，全量覆盖判定用）
        List<String> collectedKeys = new ArrayList<>();
        int upserted = upsertMenuTree(clientId, menus, null, collectedKeys);
        for (Map<String, Object> a : apis) {
            String key = String.valueOf(a.get("key"));
            if (key == null || key.isBlank() || "null".equals(key)) {
                continue;
            }
            String title = String.valueOf(a.getOrDefault("title", key));
            jdbcTemplate.update("""
                    INSERT INTO sys_permission (client_id, type, code, name, parent_id, sort, status)
                    VALUES (?, 'api', ?, ?, NULL, 0, 1)
                    ON DUPLICATE KEY UPDATE name=VALUES(name), status=1
                    """, clientId, key, title);
            collectedKeys.add("api:" + key);
            upserted++;
        }
        // 全量覆盖：本次上报未包含的既有 menu/api 条目 → 失效（参数化，空上报=全部下线）
        int retired;
        if (collectedKeys.isEmpty()) {
            retired = jdbcTemplate.update(
                    "UPDATE sys_permission SET status=0 WHERE client_id=? AND type IN ('menu','api') AND status=1",
                    clientId);
        } else {
            String placeholders = String.join(",", java.util.Collections.nCopies(collectedKeys.size(), "?"));
            Object[] params = Stream.concat(Stream.of(clientId), collectedKeys.stream()).toArray();
            retired = jdbcTemplate.update(
                    ("UPDATE sys_permission SET status=0 "
                            + "WHERE client_id=? AND type IN ('menu','api') AND status=1 "
                            + "AND CONCAT(type, ':', code) NOT IN (%s)")
                            .formatted(placeholders),
                    params);
        }
        jdbcTemplate.update("""
                INSERT INTO sys_app_client (client_id, name, status, menu_registry_json, last_sync_at)
                VALUES (?, ?, 1, ?, NOW())
                ON DUPLICATE KEY UPDATE menu_registry_json=VALUES(menu_registry_json), last_sync_at=NOW()
                """, clientId, clientId, menusYaml);
        // 上报后补默认授权：使 configured=true（过滤机制接管）而普通用户默认仍全可见（零锁死）。
        // force=false → 仅当该应用当前零绑定时补种，已人工收窄的应用不会被覆盖。
        ensureDefaultGrants(clientId, false);
        // 新接入应用上报完菜单即拥有默认 client 级角色（admin/user），无需等 auth-center 重启
        seedDefaultClientRolesFor(clientId);
        log.info("菜单上报完成: {} upsert={} retired={}", clientId, upserted, retired);
        return Map.of("upserted", upserted, "retired", retired);
    }

    /** 递归 upsert 菜单树：parentId 为树结构父亲；条目自带 parent 字段仅在无树父亲时生效。 */
    @SuppressWarnings("unchecked")
    private int upsertMenuTree(String clientId, List<Map<String, Object>> items,
                               Long parentId, List<String> collectedKeys) {
        int count = 0;
        for (Map<String, Object> m : items) {
            String key = String.valueOf(m.get("key"));
            if (key == null || key.isBlank() || "null".equals(key)) {
                continue;
            }
            String title = String.valueOf(m.getOrDefault("title", key));
            Long effParent = parentId;
            if (effParent == null && m.get("parent") != null && !String.valueOf(m.get("parent")).isBlank()) {
                effParent = findMenuIdByCode(clientId, String.valueOf(m.get("parent")));
            }
            int sort = m.get("order") == null ? 0 : Integer.parseInt(String.valueOf(m.get("order")));
            // public 标记（strict 默认最小权限下的唯一例外：「已登录即可见」菜单，如工作台/首页）
            boolean pub = isTruthy(m.get("public"));
            jdbcTemplate.update("""
                    INSERT INTO sys_permission (client_id, type, code, name, parent_id, sort, status)
                    VALUES (?, 'menu', ?, ?, ?, ?, 1)
                    ON DUPLICATE KEY UPDATE name=VALUES(name), parent_id=VALUES(parent_id),
                                            sort=VALUES(sort), status=1
                    """, clientId, key, title, effParent, sort);
            // public 标记单独更新：与全量覆盖语义一致（上次标了、本次没标 → 归 0），
            // 且列缺失（老库未补列）时只降级不中断上报主流程。
            try {
                jdbcTemplate.update(
                        "UPDATE sys_permission SET is_public=? "
                        + "WHERE client_id=? AND type='menu' AND code=?",
                        pub ? 1 : 0, clientId, key);
            } catch (Exception e) {
                log.debug("写入 public 标记失败（is_public 列缺失？）: {}", e.getMessage());
            }
            collectedKeys.add("menu:" + key);
            count++;
            if (m.get("children") instanceof List<?> kids && !kids.isEmpty()) {
                List<Map<String, Object>> childItems = new ArrayList<>();
                for (Object k : kids) {
                    if (k instanceof Map<?, ?> km) {
                        childItems.add((Map<String, Object>) km);
                    }
                }
                count += upsertMenuTree(clientId, childItems, findMenuIdByCode(clientId, key), collectedKeys);
            }
        }
        return count;
    }

    /** YAML 布尔宽松解析：{@code public: true / "true" / "yes" / 1} 均视为真。 */
    private static boolean isTruthy(Object v) {
        if (v == null) {
            return false;
        }
        if (v instanceof Boolean b) {
            return b;
        }
        String s = String.valueOf(v).trim();
        return "true".equalsIgnoreCase(s) || "yes".equalsIgnoreCase(s) || "1".equals(s);
    }

    /**
     * 校验应用上报凭据（{@code PUT /internal/clients/{clientId}/menus} 的 X-Client-Secret）。
     * {@code sys_app_client.client_secret} 为 NULL/空 = 该应用未启用 internal 上报通道，一律拒绝。
     */
    public boolean verifyClientSecret(String clientId, String secret) {
        try {
            List<String> rows = jdbcTemplate.query(
                    "SELECT client_secret FROM sys_app_client WHERE client_id=?",
                    (rs, i) -> rs.getString(1), clientId);
            if (rows.isEmpty() || rows.get(0) == null || rows.get(0).isBlank()) {
                return false;
            }
            return java.security.MessageDigest.isEqual(
                    rows.get(0).getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    secret.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.warn("校验应用上报凭据失败: {}", e.getMessage());
            return false;
        }
    }

    private Long findMenuIdByCode(String clientId, String code) {
        try {
            List<Long> ids = jdbcTemplate.query(
                    "SELECT id FROM sys_permission WHERE client_id=? AND type='menu' AND code=?",
                    (rs, i) -> rs.getLong(1), clientId, code);
            return ids.isEmpty() ? null : ids.get(0);
        } catch (Exception e) {
            return null;
        }
    }

    /** 应用最近一次上报的菜单树原文（Phase 4 管理界面用）。 */
    public String menuRegistryJson(String clientId) {
        try {
            List<String> out = jdbcTemplate.query(
                    "SELECT menu_registry_json FROM sys_app_client WHERE client_id=?",
                    (rs, i) -> rs.getString(1), clientId);
            return out.isEmpty() ? null : out.get(0);
        } catch (Exception e) {
            return null;
        }
    }

    // ───────────────────────── 授权管理（Phase 4 · 角色 × 权限点） ─────────────────────────

    /** 角色列表（platform + client 级，授权界面左栏）。 */
    public List<Map<String, Object>> listRoles() {
        try {
            return jdbcTemplate.queryForList("""
                    SELECT id, scope, client_id, code, name, description
                    FROM sys_role ORDER BY scope, client_id, code
                    """);
        } catch (Exception e) {
            log.warn("列角色失败: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /** 应用权限点明细（含失效条目，授权界面右栏树）。 */
    public List<Map<String, Object>> listPermissions(String clientId) {
        try {
            return jdbcTemplate.queryForList("""
                    SELECT id, type, code, name, parent_id, sort, status
                    FROM sys_permission WHERE client_id=? ORDER BY type, sort, id
                    """, clientId);
        } catch (Exception e) {
            log.warn("列权限点失败: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /** 角色已绑权限全码集合（client:type:code，授权界面回显）。 */
    public Set<String> rolePermissionCodes(long roleId) {
        try {
            // ⚠️ MySQL 默认模式下 || 是逻辑或不是拼接——必须用 CONCAT()
            return new HashSet<>(jdbcTemplate.queryForList("""
                    SELECT CONCAT(p.client_id, ':', p.type, ':', p.code)
                    FROM sys_role_permission rp JOIN sys_permission p ON p.id = rp.permission_id
                    WHERE rp.role_id=?
                    """, String.class, roleId));
        } catch (Exception e) {
            log.warn("查角色已绑权限失败: {}", e.getMessage());
            return new HashSet<>();
        }
    }

    /**
     * 角色授权全量覆盖：codes 形如 {@code marschat-kbops:menu:hosts}（全码）。
     * 未知 code 严格报错（授权界面只从权限树勾选，出现未知码=调用方错误）。
     */
    @org.springframework.transaction.annotation.Transactional
    public int assignRolePermissions(long roleId, Set<String> codes) {
        Integer exists = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sys_role WHERE id=?", Integer.class, roleId);
        if (exists == null || exists == 0) {
            throw new IllegalArgumentException("角色不存在: " + roleId);
        }
        List<Long> permIds = new ArrayList<>();
        for (String full : codes) {
            String[] parts = full.split(":", 3);
            if (parts.length != 3) {
                throw new IllegalArgumentException("权限码格式非法（应为 client:type:code）: " + full);
            }
            List<Long> ids = jdbcTemplate.query(
                    "SELECT id FROM sys_permission WHERE client_id=? AND type=? AND code=? AND status=1",
                    (rs, i) -> rs.getLong(1), parts[0], parts[1], parts[2]);
            if (ids.isEmpty()) {
                throw new IllegalArgumentException("权限点不存在或已失效: " + full);
            }
            permIds.add(ids.get(0));
        }
        jdbcTemplate.update("DELETE FROM sys_role_permission WHERE role_id=?", roleId);
        for (Long pid : permIds) {
            jdbcTemplate.update(
                    "INSERT INTO sys_role_permission (role_id, permission_id) VALUES (?, ?)", roleId, pid);
        }
        log.info("角色授权完成: roleId={} bound={}", roleId, permIds.size());
        return permIds.size();
    }

    // ───────────────────── 应用角色与用户绑定（Phase 4 双视角·用户×系统） ─────────────────────

    /** 创建应用级角色（client scope）。code 同 client 内唯一。 */
    @org.springframework.transaction.annotation.Transactional
    public long createClientRole(String clientId, String code, String name, String description) {
        Long dup = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sys_role WHERE scope='client' AND client_id=? AND code=?",
                Long.class, clientId, code);
        if (dup != null && dup > 0) {
            throw new IllegalArgumentException("应用角色 code 已存在: " + code);
        }
        jdbcTemplate.update(
                "INSERT INTO sys_role (scope, client_id, code, name, description) VALUES ('client', ?, ?, ?, ?)",
                clientId, code, name, description);
        return jdbcTemplate.queryForObject(
                "SELECT id FROM sys_role WHERE scope='client' AND client_id=? AND code=?",
                Long.class, clientId, code);
    }

    /** 用户在某应用的角色绑定 id 集合（sys_user_role）。 */
    public Set<Long> userClientRoleIds(long userId, String clientId) {
        try {
            return new java.util.HashSet<>(jdbcTemplate.queryForList(
                    "SELECT ur.role_id FROM sys_user_role ur JOIN sys_role r ON r.id = ur.role_id "
                    + "WHERE ur.user_id=? AND ur.client_id=?", Long.class, userId, clientId));
        } catch (Exception e) {
            log.warn("查用户应用角色失败: {}", e.getMessage());
            return new java.util.HashSet<>();
        }
    }

    /** 用户在某应用的菜单覆盖排除码集合（全码 client:menu:code，回显用）。 */
    public Set<String> userMenuOverrideCodes(long userId, String clientId) {
        try {
            // ⚠️ MySQL 默认模式下 || 是逻辑或不是拼接——必须用 CONCAT()
            return new java.util.HashSet<>(jdbcTemplate.queryForList(
                    "SELECT CONCAT(p.client_id, ':', p.type, ':', p.code) "
                    + "FROM sys_user_menu_override o JOIN sys_permission p ON p.id = o.permission_id "
                    + "WHERE o.user_id=? AND o.action='deny' AND p.client_id=? AND p.type='menu'",
                    String.class, userId, clientId));
        } catch (Exception e) {
            log.warn("查用户菜单覆盖失败: {}", e.getMessage());
            return new java.util.HashSet<>();
        }
    }

    /** 用户菜单覆盖全量覆盖（deny 集；权限码须为本应用有效 menu 权限点）。 */
    @org.springframework.transaction.annotation.Transactional
    public int assignUserMenuOverrides(long userId, String clientId, Set<String> codes) {
        List<Long> permIds = new ArrayList<>();
        for (String full : codes) {
            String[] parts = full.split(":", 3);
            if (parts.length != 3 || !"menu".equals(parts[1])) {
                throw new IllegalArgumentException("覆盖码必须为本应用 menu 权限点全码: " + full);
            }
            List<Long> ids = jdbcTemplate.query(
                    "SELECT id FROM sys_permission WHERE client_id=? AND type='menu' AND code=? AND status=1",
                    (rs, i) -> rs.getLong(1), parts[0], parts[2]);
            if (ids.isEmpty()) {
                throw new IllegalArgumentException("权限点不存在或已失效: " + full);
            }
            permIds.add(ids.get(0));
        }
        jdbcTemplate.update(
                "DELETE o FROM sys_user_menu_override o JOIN sys_permission p ON p.id = o.permission_id "
                + "WHERE o.user_id=? AND p.client_id=? AND p.type='menu'", userId, clientId);
        for (Long pid : permIds) {
            jdbcTemplate.update(
                    "INSERT INTO sys_user_menu_override (user_id, permission_id, action) VALUES (?, ?, 'deny')",
                    userId, pid);
        }
        log.info("用户菜单覆盖完成: user={} client={} denied={}", userId, clientId, permIds.size());
        return permIds.size();
    }

    /**
     * 用户在某应用的角色绑定全量覆盖（Platform 级 user.role 不受影响；
     * 超管判定走 user.role/平台角色，此处只管 client 级绑定）。
     */
    @org.springframework.transaction.annotation.Transactional
    public int assignUserClientRoles(long userId, String clientId, Set<Long> roleIds, Long operatorId) {
        for (Long rid : roleIds) {
            Map<String, Object> r = jdbcTemplate.queryForMap(
                    "SELECT scope, client_id FROM sys_role WHERE id=?", rid);
            if (!"client".equals(r.get("scope")) || !clientId.equals(r.get("client_id"))) {
                throw new IllegalArgumentException("角色 " + rid + " 不属于应用 " + clientId);
            }
        }
        // 审计要「变更前 → 变更后」对比，故先取一次旧值
        String before = clientRoleCodeList(userId, clientId);
        jdbcTemplate.update(
                "DELETE ur FROM sys_user_role ur JOIN sys_role r ON r.id = ur.role_id "
                + "WHERE ur.user_id=? AND r.scope='client' AND r.client_id=?", userId, clientId);
        for (Long rid : roleIds) {
            jdbcTemplate.update(
                    "INSERT INTO sys_user_role (user_id, role_id, client_id) VALUES (?, ?, ?)",
                    userId, rid, clientId);
        }
        String after = clientRoleCodeList(userId, clientId);
        log.info("用户应用角色绑定完成: user={} client={} bound={}", userId, clientId, roleIds.size());

        // 🔴 审计（2026-09-14 良哥要求）：**三条路径共用这一个端点**——
        //    ① 应用侧「移出本系统」（roleIds 为空）② 中心「跨应用授权」矩阵单元格改绑
        //    ③ 应用侧「添加已有用户」。故在此统一留痕，覆盖全部。
        if (operatorId != null) {
            boolean removed = roleIds.isEmpty();
            String who = usernameOf(userId);
            String detail = (removed
                    ? "将用户 " + who + " 移出应用 " + clientId + "（清空全部角色，统一身份保留）"
                    : "设置用户 " + who + " 在应用 " + clientId + " 的角色")
                    + "；变更前: " + (before.isEmpty() ? "无" : before)
                    + " → 变更后: " + (after.isEmpty() ? "无" : after);
            operationLogService.log(operatorId, usernameOf(operatorId),
                    removed ? "user.remove_from_app" : "user.client_roles",
                    "user", userId, detail, null);
        }
        return roleIds.size();
    }

    /** 某用户在某应用的角色 code 列表（逗号分隔，按 code 排序，稳定可比对） */
    private String clientRoleCodeList(long userId, String clientId) {
        List<String> codes = jdbcTemplate.queryForList(
                "SELECT r.code FROM sys_user_role ur JOIN sys_role r ON r.id = ur.role_id "
                        + "WHERE ur.user_id=? AND r.scope='client' AND r.client_id=? ORDER BY r.code",
                String.class, userId, clientId);
        return String.join(",", codes);
    }

    /** 按 id 取用户名（审计文案用；查不到回退 id 串，不抛异常） */
    private String usernameOf(Long userId) {
        if (userId == null) {
            return null;
        }
        try {
            String name = jdbcTemplate.queryForObject(
                    "SELECT username FROM user WHERE id=?", String.class, userId);
            return name == null ? String.valueOf(userId) : name;
        } catch (Exception e) {
            return String.valueOf(userId);
        }
    }

    // ═════════════════ 默认授权种子（Phase 7 · 权限统一管理「生效」） ═════════════════

    /** 启用中的应用 client_id 列表（策略端点遍历用）。 */
    public List<String> enabledClientIds() {
        try {
            return jdbcTemplate.queryForList(
                    "SELECT client_id FROM sys_app_client WHERE status=1 ORDER BY client_id", String.class);
        } catch (Exception e) {
            log.warn("列应用失败: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /** 平台角色 id（scope=platform，client_id IS NULL，按 code）。 */
    private Long platformRoleId(String code) {
        try {
            List<Long> ids = jdbcTemplate.queryForList(
                    "SELECT id FROM sys_role WHERE scope='platform' AND client_id IS NULL AND code=?",
                    Long.class, code);
            return ids.isEmpty() ? null : ids.get(0);
        } catch (Exception e) {
            return null;
        }
    }

    /** 该应用是否已有任意「角色→权限」绑定（configured 的同源判据）。 */
    public boolean hasAnyBinding(String clientId) {
        try {
            Integer n = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM sys_role_permission rp JOIN sys_permission p ON p.id=rp.permission_id WHERE p.client_id=?",
                    Integer.class, clientId);
            return n != null && n > 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 默认授权种子（按模式分流）。
     *
     * <h3>⚠️ 改造前（legacy）</h3>
     * 把应用<b>全部有效 menu 权限点</b>绑到平台 {@code user} 角色，只为把
     * {@code configured} 刷成 true。实测副作用：平台普通用户（role_id=8）因此持有
     * cosmic 8/8、kbweb 15/15、inframon 6/6、portal 2/2 全量菜单 + kbops 4 menu，
     * 外加 <b>api {@code hosts:create}（创建主机·写操作）</b> —— 「权限统一管理」名存实亡。
     *
     * <h3>改造后（strict，默认）</h3>
     * 只补发 {@code public} 菜单（应用自己在 menu-registry.yml 标记 {@code public: true}
     * 的「已登录即可见」菜单）。其余菜单与<b>所有 api</b> 一律不进默认可见集，
     * 必须由应用角色显式授权。
     * <ul>
     *   <li>菜单=可见性（public 者默认可见合理），接口=动作（默认必须拒绝）；</li>
     *   <li>{@code configured} 已与「是否全量绑定」解耦（见 {@link #permissionConfigured}），
     *       不再需要靠全量绑定刷 true；</li>
     *   <li>补发是<b>加法的、幂等的</b>，可每次启动执行，不会覆盖人工收窄。</li>
     * </ul>
     *
     * @param force legacy 模式下为 true 表示无视「已有绑定」护栏强制补发（一键回滚用）
     * @return 本次新增的绑定条数
     */
    @org.springframework.transaction.annotation.Transactional
    public int ensureDefaultGrants(String clientId, boolean force) {
        if (authzPolicy.isStrict(clientId)) {
            return authzPolicy.grantPublicMenus(clientId);
        }
        if (!force && hasAnyBinding(clientId)) {
            return 0;
        }
        return authzPolicy.grantAllMenus(clientId);
    }

    /**
     * 启动批量补种：对所有启用中的应用按各自生效模式补默认授权。
     *
     * <h3>切回 legacy 的一次性回滚</h3>
     * 若某应用曾被 strict 收敛过（{@code strict_migrated=1}），切回 legacy 时
     * <b>强制</b>把全量 menu 补回默认可见角色并清除标记 —— 这就是「一键回退且功能等价」：
     * 只做一次，之后重启不再插手，管理员可继续手工收窄。
     */
    public void syncDefaultGrantsForAllClients() {
        try {
            List<String> clients = jdbcTemplate.queryForList(
                    "SELECT client_id FROM sys_app_client WHERE status=1", String.class);
            int total = 0;
            for (String c : clients) {
                if (authzPolicy.isStrict(c)) {
                    total += ensureDefaultGrants(c, false);
                } else if (authzPolicy.isStrictMigrated(c)) {
                    total += ensureDefaultGrants(c, true);
                    authzPolicy.resetStrictMigrated(c);
                    log.info("legacy 回滚: {} 已补回全量默认菜单（一次性）", c);
                } else {
                    total += ensureDefaultGrants(c, false);
                }
            }
            log.info("默认授权种子批量补种完成（mode={}）: 新增 {} 条（客户端 {} 个）",
                    authzPolicy.mode(), total, clients.size());
        } catch (Exception e) {
            log.warn("默认授权种子批量补种失败: {}", e.getMessage());
        }
    }

    // ═════════════ strict 收敛（默认最小权限落地 + 影响面预演） ═════════════

    /**
     * 对单个应用执行 strict 收敛：补发 public 菜单 +（一次性）摘除非 public 权限绑定。
     *
     * <p>「摘除」只跑一次（{@code sys_app_client.strict_migrated}），否则管理员后续在中心
     * 手工补的授权会在每次重启时被静默回滚；{@code force=true} 可强制重跑。
     *
     * @return {publicGranted, pruned, migrated}
     */
    @org.springframework.transaction.annotation.Transactional
    public Map<String, Object> enforceStrictForClient(String clientId, boolean force) {
        if (!authzPolicy.isStrict(clientId)) {
            return Map.of("client", clientId, "strict", false, "publicGranted", 0, "pruned", 0, "migrated", false);
        }
        int granted = authzPolicy.grantPublicMenus(clientId);
        int pruned = 0;
        boolean migrated = false;
        if (force || !authzPolicy.isStrictMigrated(clientId)) {
            pruned = authzPolicy.pruneNonPublic(clientId);
            authzPolicy.markStrictMigrated(clientId);
            migrated = true;
        }
        return Map.of("client", clientId, "strict", true,
                "publicGranted", granted, "pruned", pruned, "migrated", migrated);
    }

    /**
     * 启动批量 strict 收敛（幂等）：对所有启用且生效模式为 strict 的应用执行
     * {@link #enforceStrictForClient}。legacy 应用完全不动。
     */
    public Map<String, Object> enforceStrictForAllClients() {
        int granted = 0;
        int pruned = 0;
        int clients = 0;
        try {
            List<String> all = jdbcTemplate.queryForList(
                    "SELECT client_id FROM sys_app_client WHERE status=1", String.class);
            for (String c : all) {
                if (!authzPolicy.isStrict(c)) {
                    continue;
                }
                try {
                    Map<String, Object> r = enforceStrictForClient(c, false);
                    granted += (int) r.get("publicGranted");
                    pruned += (int) r.get("pruned");
                    clients++;
                } catch (Exception e) {
                    log.warn("strict 收敛失败（跳过 {}）: {}", c, e.getMessage());
                }
            }
        } catch (Exception e) {
            log.warn("strict 收敛批量执行失败: {}", e.getMessage());
        }
        if (granted + pruned > 0) {
            log.info("strict 收敛完成: 应用 {} 个, 补发 public {} 条, 摘除非 public {} 条",
                    clients, granted, pruned);
        }
        return Map.of("clients", clients, "publicGranted", granted, "pruned", pruned);
    }

    /**
     * 影响面预演：切到 strict 后，哪些用户会失去哪些权限点。
     *
     * <p>算法：{@code after} = （收敛后仍有效的角色 → 权限）∪ public 菜单 − 用户 deny。
     * 收敛会摘掉「平台 user/admin、应用 user」三个默认角色上的非 public 绑定，
     * 故模拟时把这三个角色排除后再算，其余角色（应用 admin / 自定义角色）保持不变。
     *
     * @param clientId 应用标识
     * @param mode     {@code strict}（默认）或 {@code legacy}
     * @return 影响面明细（不改数据，只读）
     */
    public Map<String, Object> impact(String clientId, String mode) {
        boolean strict = !AuthzProperties.MODE_LEGACY.equalsIgnoreCase(mode);
        Map<String, Object> out = new HashMap<>();
        out.put("client", clientId);
        out.put("mode", strict ? AuthzProperties.MODE_STRICT : AuthzProperties.MODE_LEGACY);
        out.put("publicMenus", List.copyOf(authzPolicy.publicMenuCodes(clientId)));
        out.put("configuredNow", permissionConfigured(clientId));

        List<Map<String, Object>> users = new ArrayList<>();
        List<Long> userIds;
        try {
            userIds = jdbcTemplate.queryForList(
                    "SELECT id FROM user WHERE deleted=0 AND status=1 ORDER BY id", Long.class);
        } catch (Exception e) {
            userIds = new ArrayList<>();
        }
        for (Long uid : userIds) {
            Map<String, Object> row = new HashMap<>();
            row.put("userId", uid);
            row.put("username", usernameOf(uid));
            Set<String> platformRoles = platformRoles(uid);
            Set<String> clientRoles = clientRoleCodes(uid, clientId);
            row.put("platformRoles", List.copyOf(platformRoles));
            row.put("clientRoles", List.copyOf(clientRoles));

            Set<Long> roleIds = new HashSet<>();
            roleIds.addAll(roleIdsByCodes(platformRoles, "platform", null));
            roleIds.addAll(roleIdsByCodes(clientRoles, "client", clientId));
            expandComposites(roleIds, 0);

            Set<String> denied = deniedMenuCodes(uid, clientId);

            Set<String> before = new LinkedHashSet<>(permissionsFor(clientId, roleIds));
            before.removeAll(denied);

            Set<String> after;
            if (strict) {
                Set<Long> surviving = new HashSet<>(roleIds);
                surviving.removeAll(new HashSet<>(authzPolicy.defaultVisibleRoleIds(clientId)));
                after = new LinkedHashSet<>(permissionsFor(clientId, surviving));
                after.addAll(authzPolicy.publicMenuCodes(clientId));
            } else {
                after = new LinkedHashSet<>(before);
            }
            after.removeAll(denied);

            Set<String> lost = new LinkedHashSet<>(before);
            lost.removeAll(after);

            row.put("before", List.copyOf(before));
            row.put("after", List.copyOf(after));
            row.put("lost", List.copyOf(lost));
            row.put("affected", !lost.isEmpty());
            users.add(row);
        }
        out.put("userCount", users.size());
        out.put("affectedUserCount", users.stream().filter(u -> Boolean.TRUE.equals(u.get("affected"))).count());
        out.put("users", users);
        return out;
    }

    // ═════════════ 默认应用角色种子（Phase 8 收尾） ═════════════

    /**
     * 为全部启用中的应用补齐「默认 client 级角色」并落实默认绑定（幂等）。
     *
     * <h3>为什么需要它</h3>
     * Phase 8 上线后应用侧「本系统用户」几乎是空的——库里**只有 1 个 client 级角色**
     * （`marschat-kbops/ops-viewer`），没有任何应用有自己的角色体系。后果：
     * ① 「添加已有用户」没有默认可授角色（组件会直接中止并提示）；
     * ② 跨应用授权矩阵单元格点开是空列表；
     * ③ 「角色与菜单授权」面板无角色可配。数据是对的，但**不可用**。
     *
     * <h3>播种范围</h3>
     * 只给**真正接入统一认证平台的应用**播种 —— 判据是「已上报菜单权限点」**或**「已上报账号映射」，
     * 即 6 个自研应用（含无菜单但上报账号的 activecode）。
     * 第三方 client（memory / tokenhub / frp-manager / p3-probe…）两者皆无，
     * 给它们建角色只会污染授权矩阵与角色列表。
     *
     * <h3>播种内容（每个应用两个角色）</h3>
     * <ul>
     *   <li><b>admin「应用管理员」</b> ← 该应用**全部** menu + api 权限点；</li>
     *   <li><b>user「普通用户」</b>  ← 该应用**全部 menu** 权限点
     *       （api 不给，与平台默认授权种子同一安全姿态：菜单=可见性默认给，接口=动作默认拒）。</li>
     * </ul>
     * 并默认绑定：平台 {@code superadmin}/{@code admin} → 各应用 admin 角色；
     * 平台 {@code user} → 各应用 user 角色。这把当前「任何 auth-center 用户都能进任何应用」
     * 的 R10 现状**显式化**（行为零变化），但让授权矩阵与各应用用户列表**立刻可读、可管理**。
     *
     * <h3>绝不覆盖人工配置（沿用 {@link #ensureDefaultGrants} 的 force=false 语义）</h3>
     * 角色→权限绑定：仅当该角色**当前零权限绑定**时播种；
     * 用户→角色绑定：仅当该应用**当前零 client 级用户绑定**时播种。
     * 管理员一旦在某应用上做过增删，重启不会再插手。
     *
     * @return 明细（启动日志用）
     */
    public Map<String, Object> seedDefaultClientRoles() {
        int roles = 0;
        int permBinds = 0;
        int userBinds = 0;
        List<String> clients;
        try {
            clients = jdbcTemplate.queryForList(
                    "SELECT c.client_id FROM sys_app_client c WHERE c.status=1 "
                            + "  AND (EXISTS (SELECT 1 FROM sys_permission p "
                            + "               WHERE p.client_id = c.client_id AND p.status = 1) "
                            + "       OR EXISTS (SELECT 1 FROM app_account_mapping m "
                            + "                  WHERE m.client_id = c.client_id AND m.status = 1))",
                    String.class);
        } catch (Exception e) {
            log.warn("默认应用角色种子跳过: {}", e.getMessage());
            return Map.of("clients", 0, "roles", 0, "permissionBindings", 0, "userBindings", 0);
        }
        for (String c : clients) {
            try {
                Map<String, Object> r = seedDefaultClientRolesFor(c);
                roles += (int) r.get("roles");
                permBinds += (int) r.get("permissionBindings");
                userBinds += (int) r.get("userBindings");
            } catch (Exception e) {
                log.warn("默认应用角色种子失败（跳过 {}）: {}", c, e.getMessage());
            }
        }
        if (roles + permBinds + userBinds > 0) {
            log.info("默认应用角色种子: 新增角色 {} / 角色权限绑定 {} / 用户绑定 {}（应用 {} 个）",
                    roles, permBinds, userBinds, clients.size());
        }
        return Map.of("clients", clients.size(), "roles", roles,
                "permissionBindings", permBinds, "userBindings", userBinds);
    }

    /**
     * 单个应用的默认角色种子。
     *
     * <p>除启动时批量播种外，**菜单上报后也会调用**（{@code reportMenus}）——
     * 这样新接入的应用上报完菜单即刻拥有两个可用角色，无需等下一次 auth-center 重启。
     */
    @org.springframework.transaction.annotation.Transactional
    public Map<String, Object> seedDefaultClientRolesFor(String clientId) {
        int roles = ensureClientRoleExists(clientId, "admin", "应用管理员")
                + ensureClientRoleExists(clientId, "user", "普通用户");

        // strict：应用「普通用户」角色也只拿 public 菜单（否则平台 user → 应用 user 的
        // 默认绑定会把全量菜单又送回来，最小权限形同虚设）。
        // 应用「管理员」角色仍持有本应用全量 menu+api —— 应用管理员对自己应用全权是设计意图，
        // 也是超管/平台管理员进各应用管理台的通路（实测 admin 账号靠它保持不受影响）。
        boolean strict = authzPolicy.isStrict(clientId);
        // 应用管理员：**加法补齐**（forceTopUp=true）而非「零绑定时才播种」。
        //   理由（2026-09-15 实测踩中）：应用先上报 menu（admin 角色得到 N 条 menu 绑定），
        //   之后才上报 api 权限点（如 cosmic 的 11 个 api、infra 的 7 个 api）时，
        //   「已有绑定即跳过」的护栏会让 admin 角色**永远拿不到后补的 api 点** →
        //   该应用管理员走 SSO（中心身份非超管）时写接口 403，而菜单看着正常，属静默失效。
        //   「应用管理员对自己应用全权」是明示设计意图（非可调项），故按全量 menu+api 补齐（幂等）。
        int permBinds = bindRolePermsIfEmpty(clientId, "admin", List.of("menu", "api"), false, true)
                + bindRolePermsIfEmpty(clientId, "user", List.of("menu"), strict, false);

        int userBinds = 0;
        // ① 应用管理员 ← 平台 superadmin/admin：按 **(client, role) 判空**独立播种。
        //    语义上「超管就是每个系统的管理员」是恒定真值，且超管本就绕过 RBAC、增删皆无副作用，
        //    故不受下面「应用零绑定」护栏限制——否则像 kb-ops 这种已有 ops-viewer 绑定的应用
        //    会被整体跳过，导致它的「应用管理员」角色无人绑定（实测踩中）。
        userBinds += grantPlatformUsers(clientId, "admin",
                List.of(RoleCodes.SUPERADMIN, RoleCodes.ADMIN), true);
        // ② 普通用户 ← 平台普通用户：受「该应用零 client 级用户绑定」护栏，不覆盖人工增删。
        Integer existingUserBindings = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sys_user_role ur JOIN sys_role r ON r.id = ur.role_id "
                        + "WHERE r.scope='client' AND r.client_id=?", Integer.class, clientId);
        if (existingUserBindings == null || existingUserBindings == 0) {
            userBinds += grantPlatformUsers(clientId, "user", List.of(RoleCodes.USER), false);
        }
        return Map.of("roles", roles, "permissionBindings", permBinds, "userBindings", userBinds);
    }

    /** 确保某应用下存在指定 code 的 client 级角色；已存在返回 0（幂等） */
    private int ensureClientRoleExists(String clientId, String code, String name) {
        Integer cnt = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sys_role WHERE scope='client' AND client_id=? AND code=?",
                Integer.class, clientId, code);
        if (cnt != null && cnt > 0) {
            return 0;
        }
        jdbcTemplate.update(
                "INSERT INTO sys_role (scope, client_id, code, name) VALUES ('client', ?, ?, ?)",
                clientId, code, name);
        return 1;
    }

    /**
     * 把某应用的**全部有效权限点**（限定 type）绑定到该应用的某角色。
     *
     * <p>⚠️ 该角色**当前已有任意权限绑定**时直接返回 0 —— 这是「不覆盖人工收窄」的护栏
     * （与 {@link #ensureDefaultGrants} 的 force=false 同一取舍）。
     * 注意判据是**按角色**而非按 type：否则先绑 menu 再绑 api 时第二次会被自己的第一条挡住。
     *
     * @param publicOnly strict 下为 true：只绑 {@code public} 菜单（默认最小权限）
     * @param forceTopUp {@code true} = 跳过「零绑定」护栏，按 {@code NOT EXISTS} 条件**加法补齐**
     *                   缺失的绑定（幂等）；用于「应用管理员 = 本应用全量 menu+api」这类恒定真值。
     *                   注意它只会**新增缺失项**，不会删除人工移除的绑定，也不会覆盖其它角色。
     */
    private int bindRolePermsIfEmpty(String clientId, String roleCode, List<String> types,
                                     boolean publicOnly, boolean forceTopUp) {
        if (!forceTopUp) {
            Integer cnt = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM sys_role_permission rp JOIN sys_role r ON r.id = rp.role_id "
                            + "WHERE r.scope='client' AND r.client_id=? AND r.code=?",
                    Integer.class, clientId, roleCode);
            if (cnt != null && cnt > 0) {
                return 0;
            }
        }
        String ph = types.stream().map(t -> "?").collect(Collectors.joining(","));
        List<Object> args = new ArrayList<>();
        args.add(clientId);
        args.add(roleCode);
        args.addAll(types);
        // strict 最小权限：只绑 public 菜单（且 api 天然不在 types 里）
        String publicCond = publicOnly ? "  AND p.is_public=1 " : "";
        return jdbcTemplate.update(
                "INSERT INTO sys_role_permission (role_id, permission_id) "
                        + "SELECT r.id, p.id FROM sys_role r "
                        + "JOIN sys_permission p ON p.client_id = r.client_id "
                        + "WHERE r.scope='client' AND r.client_id=? AND r.code=? "
                        + "  AND p.type IN (" + ph + ") AND p.status=1 "
                        + publicCond
                        + "  AND NOT EXISTS (SELECT 1 FROM sys_role_permission rp "
                        + "                  WHERE rp.role_id=r.id AND rp.permission_id=p.id)",
                args.toArray());
    }

    /**
     * 把「平台角色属于 platformRoles 的活跃用户」绑定到某应用的 client 级角色（幂等）。
     *
     * @param onlyIfRoleEmpty {@code true} = 仅当该 (应用, 角色) 当前**零绑定**时才播种
     *                        （用于「应用管理员」这类应恒有绑定的角色，避免人工清空后被反复重加）
     */
    private int grantPlatformUsers(String clientId, String clientRoleCode, List<String> platformRoles,
                                   boolean onlyIfRoleEmpty) {
        if (onlyIfRoleEmpty) {
            Integer cnt = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM sys_user_role ur JOIN sys_role r ON r.id = ur.role_id "
                            + "WHERE r.scope='client' AND r.client_id=? AND r.code=?",
                    Integer.class, clientId, clientRoleCode);
            if (cnt != null && cnt > 0) {
                return 0;
            }
        }
        String ph = platformRoles.stream().map(x -> "?").collect(Collectors.joining(","));
        List<Object> args = new ArrayList<>();
        args.add(clientId);   // SELECT 里的 client_id
        args.add(clientId);   // JOIN 条件
        args.add(clientRoleCode);
        args.addAll(platformRoles);
        args.add(clientId);   // NOT EXISTS 条件
        return jdbcTemplate.update(
                "INSERT INTO sys_user_role (user_id, role_id, client_id) "
                        + "SELECT u.id, r.id, ? FROM user u "
                        + "JOIN sys_role r ON r.scope='client' AND r.client_id=? AND r.code=? "
                        + "WHERE u.deleted=0 AND u.status=1 AND u.role IN (" + ph + ") "
                        + "  AND NOT EXISTS (SELECT 1 FROM sys_user_role ur "
                        + "                  WHERE ur.user_id=u.id AND ur.role_id=r.id AND ur.client_id=?)",
                args.toArray());
    }
}
