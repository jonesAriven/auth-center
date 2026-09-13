package com.marschat.authcenter.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
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
 *   configured = 该应用在 sys_permission 里是否存在任何记录
 * </pre>
 * <b>R10 默认策略</b>：configured=false 时调用方（前端守卫 / 拦截器）按「行为不变」放行，
 * 保证存量应用零波及。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PermissionService {

    private final JdbcTemplate jdbcTemplate;

    /** 单次 composite 展开深度上限（防环）。 */
    private static final int MAX_DEPTH = 8;

    public Map<String, Object> computeForUser(long userId, String clientId) {
        Set<String> platformRoles = platformRoles(userId);
        Set<String> clientRoleCodes = clientRoleCodes(userId, clientId);

        Set<String> roleCodes = new LinkedHashSet<>(platformRoles);
        roleCodes.addAll(clientRoleCodes);
        Set<Long> roleIds = roleIdsByCodes(userId, clientId, roleCodes);
        expandComposites(roleIds, 0);
        roleCodes.addAll(roleCodesByIds(roleIds));

        Set<String> permissions = permissionsFor(clientId, roleIds);
        boolean configured = permissionConfigured(clientId);
        // R9 用户级减法：角色默认权限 − 用户 override（deny）——只减不加
        permissions.removeAll(deniedMenuCodes(userId, clientId));

        Map<String, Object> out = new HashMap<>();
        out.put("client", clientId);
        out.put("platformRoles", List.copyOf(platformRoles));
        out.put("roles", List.copyOf(roleCodes));
        out.put("permissions", List.copyOf(permissions));
        out.put("configured", configured);
        return out;
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

    /** 角色 code → id（platform 绑定按 code+scope=platform；client 绑定按 code+scope=client+本应用）。 */
    private Set<Long> roleIdsByCodes(long userId, String clientId, Set<String> codes) {
        Set<Long> out = new HashSet<>();
        if (codes.isEmpty()) {
            return out;
        }
        String placeholders = String.join(",", java.util.Collections.nCopies(codes.size(), "?"));
        Object[] params = Stream.concat(Arrays.stream(codes.toArray()), Stream.of(clientId)).toArray();
        try {
            out.addAll(jdbcTemplate.queryForList("""
                    SELECT DISTINCT r.id FROM sys_role r
                    WHERE r.code IN (%s)
                      AND (r.scope='platform' OR (r.scope='client' AND r.client_id=?))
                    """.formatted(placeholders), Long.class, params));
        } catch (Exception e) {
            log.debug("角色 id 解析失败: {}", e.getMessage());
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

    private boolean permissionConfigured(String clientId) {
        try {
            Integer n = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM sys_permission WHERE client_id=?", Integer.class, clientId);
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
     */
    @SuppressWarnings("unchecked")
    public Map<String, Integer> reportMenus(String clientId, String menusYaml) {
        org.yaml.snakeyaml.Yaml yaml = new org.yaml.snakeyaml.Yaml();
        Object root = yaml.load(menusYaml);
        List<Map<String, Object>> menus = new ArrayList<>();
        if (root instanceof Map<?, ?> m && m.get("menus") instanceof List<?> l) {
            for (Object o : l) {
                if (o instanceof Map<?, ?> item) {
                    menus.add((Map<String, Object>) item);
                }
            }
        }
        List<String> collectedKeys = new ArrayList<>();
        int upserted = upsertMenuTree(clientId, menus, null, collectedKeys);
        // 全量覆盖：本次上报未包含的既有菜单 → 失效（参数化 NOT IN，空上报=全部下线）
        int retired;
        if (collectedKeys.isEmpty()) {
            retired = jdbcTemplate.update(
                    "UPDATE sys_permission SET status=0 WHERE client_id=? AND type='menu' AND status=1",
                    clientId);
        } else {
            String placeholders = String.join(",", java.util.Collections.nCopies(collectedKeys.size(), "?"));
            Object[] params = Stream.concat(Stream.of(clientId), collectedKeys.stream()).toArray();
            retired = jdbcTemplate.update(
                    ("UPDATE sys_permission SET status=0 "
                            + "WHERE client_id=? AND type='menu' AND status=1 AND code NOT IN (%s)")
                            .formatted(placeholders),
                    params);
        }
        jdbcTemplate.update("""
                INSERT INTO sys_app_client (client_id, name, status, menu_registry_json, last_sync_at)
                VALUES (?, ?, 1, ?, NOW())
                ON DUPLICATE KEY UPDATE menu_registry_json=VALUES(menu_registry_json), last_sync_at=NOW()
                """, clientId, clientId, menusYaml);
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
            jdbcTemplate.update("""
                    INSERT INTO sys_permission (client_id, type, code, name, parent_id, sort, status)
                    VALUES (?, 'menu', ?, ?, ?, ?, 1)
                    ON DUPLICATE KEY UPDATE name=VALUES(name), parent_id=VALUES(parent_id),
                                            sort=VALUES(sort), status=1
                    """, clientId, key, title, effParent, sort);
            collectedKeys.add(key);
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
            return new HashSet<>(jdbcTemplate.queryForList("""
                    SELECT p.client_id || ':' || p.type || ':' || p.code
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
            return new java.util.HashSet<>(jdbcTemplate.queryForList(
                    "SELECT p.client_id || ':' || p.type || ':' || p.code "
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
    public int assignUserClientRoles(long userId, String clientId, Set<Long> roleIds) {
        for (Long rid : roleIds) {
            Map<String, Object> r = jdbcTemplate.queryForMap(
                    "SELECT scope, client_id FROM sys_role WHERE id=?", rid);
            if (!"client".equals(r.get("scope")) || !clientId.equals(r.get("client_id"))) {
                throw new IllegalArgumentException("角色 " + rid + " 不属于应用 " + clientId);
            }
        }
        jdbcTemplate.update(
                "DELETE ur FROM sys_user_role ur JOIN sys_role r ON r.id = ur.role_id "
                + "WHERE ur.user_id=? AND r.scope='client' AND r.client_id=?", userId, clientId);
        for (Long rid : roleIds) {
            jdbcTemplate.update(
                    "INSERT INTO sys_user_role (user_id, role_id, client_id) VALUES (?, ?, ?)",
                    userId, rid, clientId);
        }
        log.info("用户应用角色绑定完成: user={} client={} bound={}", userId, clientId, roleIds.size());
        return roleIds.size();
    }
}
