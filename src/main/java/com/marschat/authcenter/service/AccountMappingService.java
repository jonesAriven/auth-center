package com.marschat.authcenter.service;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 账号映射中心（统一身份 ↔ 各系统本地账号）。
 *
 * <p>初衷对齐：平台要「用户统一管理 + 账号映射」。历史实现里各应用各有一套账号库
 * （portal.sys_user / activecode.admin_user / cosmic.users / infra 配置式管理员），
 * 中心看不到、管不着。本服务把这些**应用侧本地账号**登记进中心，并尽量自动认领到
 * 统一身份（按 username / email 精确唯一匹配），剩余歧义/未匹配的交给管理员手工绑定。
 *
 * <p>数据流：
 * <pre>
 *   ① 应用启动/变更 → PUT /internal/clients/{clientId}/accounts（X-Client-Secret）
 *      → syncLocalAccounts()：upsert 全量覆盖 + 自动认领 + 旧账号置失效
 *   ② 管理员界面 → GET  /admin/mappings（列表）/ /admin/users/{id}/mappings（按人聚合）
 *      → POST /admin/mappings/{id}/bind|unbind（手工绑定/解绑）
 * </pre>
 *
 * <p>安全口径：自动认领只接受**唯一命中**（username 或 email 精确匹配且结果唯一），
 * 0 命中（新账号）与 &gt;1 命中（歧义）一律留待人工，避免把账号错绑到别人身份上。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccountMappingService {

    private final JdbcTemplate jdbcTemplate;

    /** 应用上报的单条本地账号。 */
    @Data
    public static class LocalAccount {
        /** 应用侧本地账号标识（必填） */
        private String account;
        /** 应用侧显示名（可选） */
        private String name;
    }

    /**
     * 应用上报本地账号清单（全量覆盖语义）。
     *
     * <p>与菜单上报同构：本次清单 = 应用当前真实存在的账号全集，
     * 未出现在清单中的既有映射置 {@code status=0}（识别"已删除账号"），
     * 不做物理删除（保留审计与历史绑定关系）。
     *
     * @return {upserted, retired, claimed}
     */
    @Transactional
    public Map<String, Object> syncLocalAccounts(String clientId, List<LocalAccount> accounts) {
        List<String> seen = new ArrayList<>();
        int upserted = 0;
        int claimed = 0;
        if (accounts != null) {
            for (LocalAccount a : accounts) {
                if (a == null || a.getAccount() == null || a.getAccount().isBlank()) {
                    continue;
                }
                String acc = a.getAccount().trim();
                if (seen.contains(acc)) {
                    continue;
                }
                seen.add(acc);
                String name = a.getName() == null ? null : a.getName().trim();
                jdbcTemplate.update("""
                        INSERT INTO app_account_mapping
                            (user_id, client_id, local_account, local_display_name, source, status, last_seen_at)
                        VALUES (NULL, ?, ?, ?, 'report', 1, NOW())
                        ON DUPLICATE KEY UPDATE
                            local_display_name = VALUES(local_display_name),
                            status = 1,
                            last_seen_at = NOW()
                        """, clientId, acc, name);
                upserted++;
                claimed += autoClaim(clientId, acc);
            }
        }
        int retired;
        if (seen.isEmpty()) {
            retired = jdbcTemplate.update(
                    "UPDATE app_account_mapping SET status=0 WHERE client_id=? AND status=1", clientId);
        } else {
            String placeholders = String.join(",", java.util.Collections.nCopies(seen.size(), "?"));
            Object[] params = java.util.stream.Stream
                    .concat(java.util.stream.Stream.of(clientId), seen.stream()).toArray();
            retired = jdbcTemplate.update(
                    ("UPDATE app_account_mapping SET status=0 "
                            + "WHERE client_id=? AND status=1 AND local_account NOT IN (%s)")
                            .formatted(placeholders),
                    params);
        }
        log.info("账号映射上报完成: {} upsert={} retired={} claimed={}", clientId, upserted, retired, claimed);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("upserted", upserted);
        out.put("retired", retired);
        out.put("claimed", claimed);
        return out;
    }

    /**
     * 自动认领：把「未绑定」的映射按 local_account 匹配中心 user.username / user.email。
     * 仅在**唯一命中**时认领（0 命中=新账号，&gt;1 命中=歧义），其余留待人工绑定。
     */
    private int autoClaim(String clientId, String localAccount) {
        try {
            List<Long> ids = jdbcTemplate.query(
                    "SELECT id FROM user WHERE deleted=0 AND (username=? OR (email IS NOT NULL AND email=?))",
                    (rs, i) -> rs.getLong(1), localAccount, localAccount);
            List<Long> distinct = ids.stream().distinct().toList();
            if (distinct.size() != 1) {
                return 0;
            }
            return jdbcTemplate.update("""
                    UPDATE app_account_mapping SET user_id=?, source='auto', linked_at=NOW()
                    WHERE client_id=? AND local_account=? AND user_id IS NULL
                    """, distinct.get(0), clientId, localAccount);
        } catch (Exception e) {
            log.debug("自动认领失败: {} {} {}", clientId, localAccount, e.getMessage());
            return 0;
        }
    }

    /** 映射列表（分页；可按应用 / 中心用户 / 关键字过滤）。 */
    public Map<String, Object> listMappings(String clientId, Long userId, String keyword, int page, int size) {
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        List<Object> params = new ArrayList<>();
        if (clientId != null && !clientId.isBlank()) {
            where.append(" AND m.client_id=?");
            params.add(clientId);
        }
        if (userId != null) {
            where.append(" AND m.user_id=?");
            params.add(userId);
        }
        if (keyword != null && !keyword.isBlank()) {
            where.append(" AND (m.local_account LIKE ? OR m.local_display_name LIKE ? OR u.username LIKE ?)");
            String kw = "%" + keyword.trim() + "%";
            params.add(kw);
            params.add(kw);
            params.add(kw);
        }
        Integer total = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM app_account_mapping m LEFT JOIN user u ON u.id=m.user_id" + where,
                Integer.class, params.toArray());
        int safeSize = size <= 0 ? 20 : Math.min(size, 200);
        int safePage = page <= 0 ? 1 : page;
        List<Object> pageParams = new ArrayList<>(params);
        pageParams.add(safeSize);
        pageParams.add((safePage - 1) * safeSize);
        List<Map<String, Object>> rows = jdbcTemplate.queryForList("""
                SELECT m.id, m.client_id, m.local_account, m.local_display_name, m.user_id,
                       u.username AS platform_username, u.nickname AS platform_nickname,
                       u.email AS platform_email, u.role AS platform_role,
                       m.source, m.status, m.linked_at, m.last_seen_at
                FROM app_account_mapping m LEFT JOIN user u ON u.id = m.user_id
                """ + where + " ORDER BY m.client_id, m.status DESC, m.local_account LIMIT ? OFFSET ?",
                pageParams.toArray());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("total", total == null ? 0 : total);
        out.put("page", safePage);
        out.put("size", safeSize);
        out.put("records", rows);
        return out;
    }

    /** 某个中心统一用户在**各系统**的账号映射（"这个人有哪些系统账号"聚合视图）。 */
    public List<Map<String, Object>> listByUser(long userId) {
        try {
            return jdbcTemplate.queryForList("""
                    SELECT id, client_id, local_account, local_display_name, source, status, linked_at, last_seen_at
                    FROM app_account_mapping
                    WHERE user_id=? AND status=1
                    ORDER BY client_id
                    """, userId);
        } catch (Exception e) {
            log.warn("查用户账号映射失败: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /** 覆盖概览：每个应用 总账号 / 已认领 / 待绑定。管理界面顶部卡片用。 */
    public List<Map<String, Object>> summary() {
        try {
            return jdbcTemplate.queryForList("""
                    SELECT client_id,
                           COUNT(*) AS total,
                           SUM(CASE WHEN user_id IS NOT NULL THEN 1 ELSE 0 END) AS linked,
                           SUM(CASE WHEN user_id IS NULL THEN 1 ELSE 0 END) AS pending
                    FROM app_account_mapping
                    WHERE status=1
                    GROUP BY client_id
                    ORDER BY client_id
                    """);
        } catch (Exception e) {
            log.warn("账号映射概览失败: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /** 管理员手工绑定：把某条应用本地账号认领到指定中心用户。 */
    @Transactional
    public int bindMapping(long mappingId, long userId) {
        Integer userExists = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM user WHERE id=? AND deleted=0", Integer.class, userId);
        if (userExists == null || userExists == 0) {
            throw new IllegalArgumentException("中心用户不存在或已删除: " + userId);
        }
        Integer mappingExists = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM app_account_mapping WHERE id=?", Integer.class, mappingId);
        if (mappingExists == null || mappingExists == 0) {
            throw new IllegalArgumentException("映射记录不存在: " + mappingId);
        }
        return jdbcTemplate.update(
                "UPDATE app_account_mapping SET user_id=?, source='manual', linked_at=NOW() WHERE id=?",
                userId, mappingId);
    }

    /** 解绑：清空中心用户关联，回到「待绑定」状态。 */
    @Transactional
    public int unbindMapping(long mappingId) {
        return jdbcTemplate.update(
                "UPDATE app_account_mapping SET user_id=NULL, source='report', linked_at=NULL WHERE id=?",
                mappingId);
    }
}
