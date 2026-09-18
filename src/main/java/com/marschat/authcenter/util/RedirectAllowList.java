package com.marschat.authcenter.util;

import java.net.URI;

/**
 * 回跳地址白名单：本平台域名（*.marschat.online）+ 本机/内网开发地址。
 *
 * <p>判据与 {@code AuthController#isAllowedRedirect} 完全一致（刻意重复：该方法位于
 * 12 应用登出主链路 {@code /auth/slo} 的关键路径上，为一个装饰性功能去重构枢纽不划算。
 * 后续如需收敛，两处应同时修改并补统一单测）。
 *
 * <p>本类无状态、线程安全。
 */
public final class RedirectAllowList {

    private RedirectAllowList() {
    }

    /**
     * 校验回跳地址是否落在平台白名单内。
     *
     * <p>判据：scheme ∈ {http, https}；host 非空；host == marschat.online 或
     * endswith(".marschat.online") → true；host ∈ {localhost, 127.0.0.1, ::1, [::1]} → true；
     * RFC1918 私网（10/8、192.168/16、172.16/12）→ true；其余 false；解析异常 false。
     *
     * @param uri 待校验的回跳地址（可为 null / 空白）
     * @return 在白名单内返回 true；解析失败或不在白名单返回 false
     */
    public static boolean isAllowed(String uri) {
        if (uri == null || uri.isBlank()) {
            return false;
        }
        try {
            URI u = URI.create(uri.trim());
            String scheme = u.getScheme();
            if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                return false;
            }
            String host = u.getHost();
            if (host == null || host.isBlank()) {
                return false;
            }
            host = host.toLowerCase();
            if (host.equals("marschat.online") || host.endsWith(".marschat.online")) {
                return true;
            }
            // 本机 / 内网开发地址（本地联调、局域网直连）
            if (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("::1")
                    || host.equals("[::1]")) {
                return true;
            }
            // RFC 1918 私网：10/8、192.168/16、172.16/12
            String[] octets = host.split("\\.");
            if (octets.length == 4 && isNumericOctets(octets)) {
                int a = Integer.parseInt(octets[0]);
                int b = Integer.parseInt(octets[1]);
                if (a == 10 || a == 192 && b == 168 || a == 172 && b >= 16 && b <= 31) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isNumericOctets(String[] parts) {
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3) {
                return false;
            }
            for (int i = 0; i < p.length(); i++) {
                if (!Character.isDigit(p.charAt(i))) {
                    return false;
                }
            }
        }
        return true;
    }
}
