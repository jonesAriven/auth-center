package com.marschat.authcenter.service;

import com.marschat.authcenter.config.AuthzProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 授权默认策略（{@code strict = 默认最小权限} / {@code legacy = 默认全给}）的执行层。
 *
 * <h3>改造前的病（实测，非推测）</h3>
 * 平台「普通用户」角色（{@code role_id=8}）被绑了 36 条权限点：cosmic 8/8、kbweb 15/15、
 * inframon 6/6、portal 2/2 全量 menu，外加 kbops 4 menu + <b>api {@code hosts:create}</b>
 * （创建主机·写操作）。根因是 {@code ensureDefaultGrants} 为了把 {@code configured} 从 false
 * 刷成 true，把应用<b>全部 menu 权限点</b>绑给了平台 user 角色。
 * → 任何平台普通用户 = 拥有 5 个应用全部菜单 + 在 kb-ops 创建主机的写权限。
 * 「权限统一管理」名存实亡，且比不做更危险（管理员误以为已管控）。
 *
 * <h3>改造后的语义</h3>
 * <ol>
 *   <li><b>默认最小权限</b>：平台 {@code user}/{@code admin}、应用 {@code user} 角色
 *       <b>只持有 {@code public} 菜单</b>（应用在自己 menu-registry.yml 里标记
 *       {@code public: true} 的「已登录即可见」菜单，如工作台/首页）；</li>
 *   <li>其余 menu/api 必须由<b>应用角色显式授权</b>才生效；</li>
 *   <li>{@code api} 权限点<b>永不</b>进入默认可见集（接口=动作，默认必须拒绝）；</li>
 *   <li>{@code configured} 与「是否全量绑定」解耦：有 public 菜单或有任意角色-权限绑定
 *       即为 true，绝不再靠全量绑定刷 true。</li>
 * </ol>
 *
 * <h3>为什么「收敛」是一次性的</h3>
 * 摘除存量绑定（{@link #pruneNonPublic}）会真的删数据，若每次启动都跑，管理员在中心
 * 手工补的授权会被静默回滚。故用 {@code sys_app_client.strict_migrated} 做一次性标记；
 * 需要重新收敛时调用 {@code POST /admin/authz/migrate?force=true}。
 * 而「补发 public 菜单」({@link #grantPublicMenus}) 是加法的、幂等的，每次启动都跑，
 * 保证应用后续新标记 public 的菜单能自动生效。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthzPolicyService {

    private final JdbcTemplate jdbcTemplate;

    private final AuthzProperties authzProperties;

    // ───────────────────────── 模式判定 ─────────────────────────

    /** 全局模式（strict / legacy）。 */
    public String mode() {
        return authzProperties.isGlobalStrict() ? AuthzProperties.MODE_STRICT : AuthzProperties.MODE_LEGACY;
    }

    /** 灰度名单（全局 legacy 时仅这些 client 走 strict）。 */
    public List<String> strictClients() {
        return List.copyOf(authzProperties.getStrictClients());
    }

    /** 某应用实际是否按「默认最小权限」计算。 */
    public boolean isStrict(String clientId) {
        return authzProperties.isStrictFor(clientId);
    }

    // ───────────────────────── public 菜单 ─────────────────────────

    /**
     * 本应用「已登录即可见」的 public 菜单全码集合（{@code client:menu:code}）。
     * is_public 列缺失（老库未补列）时返回空集 —— 降级为「零 public」而非抛错。
     */
    public Set<String> publicMenuCodes(String clientId) {
        Set<String> out = new LinkedHashSet<>();
        try {
            List<String> codes = jdbcTemplate.queryForList(
                    "SELECT code FROM sys_permission "
                    + "WHERE client_id=? AND type='menu' AND status=1 AND is_public=1",
                    String.class, clientId);
            for (String c : codes) {
                out.add(clientId + ":menu:" + c);
            }
        } catch (Exception e) {
            log.debug("读 public 菜单失败（is_public 列可能尚未补上）: {}", e.getMessage());
        }
        return out;
    }

    /** 本应用是否存在 public 菜单（configured 判据之一）。 */
    public boolean hasPublicMenu(String clientId) {
        try {
            Integer n = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM sys_permission "
                    + "WHERE client_id=? AND type='menu' AND status=1 AND is_public=1",
                    Integer.class, clientId);
            return n != null && n > 0;
        } catch (Exception e) {
            return false;
        }
    }

    // ───────────────────────── 授权动作 ─────────────────────────

    /**
     * 补发 public 菜单到「默认可见角色」（平台 user/admin + 应用 user）。
     * 加法、幂等，可每次启动执行。
     *
     * @return 新增绑定条数
     */
    @Transactional
    public int grantPublicMenus(String clientId) {
        int total = 0;
        for (Long roleId : defaultVisibleRoleIds(clientId)) {
            total += jdbcTemplate.update(
                    "INSERT INTO sys_role_permission (role_id, permission_id) "
                    + "SELECT ?, p.id FROM sys_permission p "
                    + "WHERE p.client_id=? AND p.type='menu' AND p.status=1 AND p.is_public=1 "
                    + "  AND NOT EXISTS (SELECT 1 FROM sys_role_permission rp "
                    + "                  WHERE rp.role_id=? AND rp.permission_id=p.id)",
                    roleId, clientId, roleId);
        }
        if (total > 0) {
            log.info("strict 默认授权: {} 补发 public 菜单 {} 条", clientId, total);
        }
        return total;
    }

    /**
     * 一键回滚：把<b>全部有效 menu</b>补发给默认可见角色（legacy「默认全给」等价态）。
     * 只补 menu、不补 api —— 接口=动作，任何模式下都不应自动授予。
     *
     * @return 新增绑定条数
     */
    @Transactional
    public int grantAllMenus(String clientId) {
        int total = 0;
        for (Long roleId : defaultVisibleRoleIds(clientId)) {
            total += jdbcTemplate.update(
                    "INSERT INTO sys_role_permission (role_id, permission_id) "
                    + "SELECT ?, p.id FROM sys_permission p "
                    + "WHERE p.client_id=? AND p.type='menu' AND p.status=1 "
                    + "  AND NOT EXISTS (SELECT 1 FROM sys_role_permission rp "
                    + "                  WHERE rp.role_id=? AND rp.permission_id=p.id)",
                    roleId, clientId, roleId);
        }
        if (total > 0) {
            log.info("legacy 回滚: {} 补发全量菜单 {} 条", clientId, total);
        }
        return total;
    }

    /**
     * 摘除默认可见角色上的<b>非 public</b>权限绑定（strict 收敛，会真删数据）。
     *
     * <p>覆盖范围（刻意不含「应用 admin」——应用管理员对自己应用的全权是设计意图）：
     * <ul>
     *   <li>{@code scope='platform' AND code IN ('user','admin')}（平台默认角色）；</li>
     *   <li>{@code scope='client' AND client_id=? AND code='user'}（应用普通用户角色）。</li>
     * </ul>
     * 删除条件：非「{@code type='menu' AND is_public=1}」的绑定 —— 即所有 api 权限点
     * （含 kbops {@code hosts:create}）与所有非 public 菜单。
     *
     * @return 删除条数
     */
    @Transactional
    public int pruneNonPublic(String clientId) {
        int n = jdbcTemplate.update(
                "DELETE rp FROM sys_role_permission rp "
                + "JOIN sys_role r ON r.id = rp.role_id "
                + "JOIN sys_permission p ON p.id = rp.permission_id "
                + "WHERE p.client_id = ? "
                + "  AND ( (r.scope='platform' AND r.code IN ('user','admin')) "
                + "     OR (r.scope='client' AND r.client_id = ? AND r.code = 'user') ) "
                + "  AND NOT (p.type='menu' AND p.is_public = 1)",
                clientId, clientId);
        if (n > 0) {
            log.info("strict 收敛: {} 摘除非 public 权限绑定 {} 条", clientId, n);
        }
        return n;
    }

    // ───────────────────────── 一次性迁移标记 ─────────────────────────

    /** 该应用是否已完成 strict 收敛（{@code sys_app_client.strict_migrated}）。 */
    public boolean isStrictMigrated(String clientId) {
        try {
            Integer n = jdbcTemplate.queryForObject(
                    "SELECT strict_migrated FROM sys_app_client WHERE client_id=?",
                    Integer.class, clientId);
            return n != null && n == 1;
        } catch (Exception e) {
            // 列缺失 → 视作未迁移（会走一次收敛；列缺失时 prune 也会因 is_public 缺失而空转）
            return false;
        }
    }

    /** 标记该应用已完成 strict 收敛。 */
    public void markStrictMigrated(String clientId) {
        try {
            jdbcTemplate.update("UPDATE sys_app_client SET strict_migrated=1 WHERE client_id=?", clientId);
        } catch (Exception e) {
            log.warn("标记 strict_migrated 失败: {} {}", clientId, e.getMessage());
        }
    }

    /**
     * 清除收敛标记（切回 legacy 完成一次性回滚后调用）。
     * 清掉之后：再切回 strict 会重新收敛一次，不会留下「已迁移」的假象。
     */
    public void resetStrictMigrated(String clientId) {
        try {
            jdbcTemplate.update("UPDATE sys_app_client SET strict_migrated=0 WHERE client_id=?", clientId);
        } catch (Exception e) {
            log.warn("清除 strict_migrated 失败: {} {}", clientId, e.getMessage());
        }
    }

    /** 该应用是否上报过任意有效权限点（menu/api 定义，与是否授权无关）。 */
    public boolean hasAnyPermission(String clientId) {
        try {
            Integer n = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM sys_permission WHERE client_id=? AND status=1",
                    Integer.class, clientId);
            return n != null && n > 0;
        } catch (Exception e) {
            return false;
        }
    }

    // ───────────────────────── 内部 ─────────────────────────

    /**
     * 「默认可见角色」id：平台 user/admin + 本应用 client 级 user。
     * 应用 admin 角色不在其中 —— 它本来就持有本应用全量权限，无需重复授予。
     */
    public List<Long> defaultVisibleRoleIds(String clientId) {
        List<Long> ids = new ArrayList<>();
        try {
            ids.addAll(jdbcTemplate.queryForList(
                    "SELECT id FROM sys_role WHERE scope='platform' AND client_id IS NULL "
                    + "AND code IN ('user','admin') ORDER BY id", Long.class));
            ids.addAll(jdbcTemplate.queryForList(
                    "SELECT id FROM sys_role WHERE scope='client' AND client_id=? AND code='user'",
                    Long.class, clientId));
        } catch (Exception e) {
            log.warn("解析默认可见角色失败: {}", e.getMessage());
        }
        return ids;
    }
}
