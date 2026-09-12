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

        Map<String, Object> out = new HashMap<>();
        out.put("client", clientId);
        out.put("platformRoles", List.copyOf(platformRoles));
        out.put("roles", List.copyOf(roleCodes));
        out.put("permissions", List.copyOf(permissions));
        out.put("configured", configured);
        return out;
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
        int upserted = 0;
        for (Map<String, Object> m : menus) {
            String key = String.valueOf(m.get("key"));
            String title = String.valueOf(m.getOrDefault("title", key));
            String parent = m.get("parent") == null || String.valueOf(m.get("parent")).isBlank()
                    ? null : String.valueOf(m.get("parent"));
            int sort = m.get("order") == null ? 0 : Integer.parseInt(String.valueOf(m.get("order")));
            Long parentId = parent == null ? null : findMenuIdByCode(clientId, parent);
            jdbcTemplate.update("""
                    INSERT INTO sys_permission (client_id, type, code, name, parent_id, sort, status)
                    VALUES (?, 'menu', ?, ?, ?, ?, 1)
                    ON DUPLICATE KEY UPDATE name=VALUES(name), parent_id=VALUES(parent_id),
                                            sort=VALUES(sort), status=1
                    """, clientId, key, title, parentId, sort);
            upserted++;
        }
        // 全量覆盖：本次上报未包含的既有菜单 → 失效（子查询自连接避免同表 UPDATE/SELECT 冲突）
        int retired = jdbcTemplate.update("""
                UPDATE sys_permission p
                LEFT JOIN sys_permission keep_p
                  ON keep_p.id = p.id AND keep_p.status = 1
                SET p.status = 0
                WHERE p.client_id=? AND p.type='menu' AND p.status=1
                  AND p.code NOT IN (%s)
                """.formatted(menus.isEmpty() ? "''" : menus.stream()
                        .map(m -> "'" + String.valueOf(m.get("key")).replace("'", "''") + "'")
                        .collect(Collectors.joining(","))),
                clientId);
        jdbcTemplate.update("""
                INSERT INTO sys_app_client (client_id, name, status, menu_registry_json, last_sync_at)
                VALUES (?, ?, 1, ?, NOW())
                ON DUPLICATE KEY UPDATE menu_registry_json=VALUES(menu_registry_json), last_sync_at=NOW()
                """, clientId, clientId, menusYaml);
        log.info("菜单上报完成: {} upsert={} retired={}", clientId, upserted, retired);
        return Map.of("upserted", upserted, "retired", retired);
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
}
