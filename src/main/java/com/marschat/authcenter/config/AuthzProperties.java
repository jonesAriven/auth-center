package com.marschat.authcenter.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 授权默认策略配置（{@code marschat.authz.*}）。
 *
 * <h3>背景（为什么必须可灰度）</h3>
 * auth-center 是 12 应用的认证枢纽，"默认全给"改成"默认最小权限"是全站可见性的一次性跳变。
 * 故提供两级开关：
 * <ul>
 *   <li><b>全局</b>：{@code marschat.authz.mode = strict|legacy}，默认 {@code strict}。</li>
 *   <li><b>按应用灰度</b>：{@code marschat.authz.strict-clients: marschat-portal,...}
 *       —— 当全局仍为 {@code legacy} 时，只有列出的应用走 strict（先在 portal 验证）。</li>
 * </ul>
 *
 * <pre>
 * marschat:
 *   authz:
 *     mode: ${MARSCHAT_AUTHZ_MODE:strict}
 *     strict-clients: ${MARSCHAT_AUTHZ_STRICT_CLIENTS:}
 * </pre>
 */
@Component
@ConfigurationProperties(prefix = "marschat.authz")
public class AuthzProperties {

    /** 默认最小权限：平台/应用默认角色只持有 public 菜单，其余须显式授权。 */
    public static final String MODE_STRICT = "strict";

    /** 一键回滚：恢复改造前「默认全量菜单」行为。 */
    public static final String MODE_LEGACY = "legacy";

    /** 全局模式，默认 strict。 */
    private String mode = MODE_STRICT;

    /** 灰度名单：全局 legacy 时，仅这些 client 走 strict。 */
    private List<String> strictClients = new ArrayList<>();

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = normalize(mode);
    }

    public List<String> getStrictClients() {
        return strictClients;
    }

    public void setStrictClients(List<String> strictClients) {
        this.strictClients = strictClients == null ? new ArrayList<>() : new ArrayList<>(strictClients);
    }

    /** 全局是否 strict。 */
    public boolean isGlobalStrict() {
        return MODE_STRICT.equalsIgnoreCase(normalize(mode));
    }

    /**
     * 某应用实际生效的模式是否为 strict。
     *
     * @param clientId 应用标识（{@code null} 时按全局模式判定）
     * @return true = 该应用按「默认最小权限」计算
     */
    public boolean isStrictFor(String clientId) {
        if (isGlobalStrict()) {
            return true;
        }
        if (clientId == null || clientId.isBlank()) {
            return false;
        }
        for (String c : strictClients) {
            if (c != null && c.trim().equals(clientId)) {
                return true;
            }
        }
        return false;
    }

    private static String normalize(String v) {
        return v == null ? MODE_STRICT : v.trim().toLowerCase(java.util.Locale.ROOT);
    }
}
