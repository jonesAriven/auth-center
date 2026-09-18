package com.marschat.authcenter.controller;

import com.marschat.authcenter.util.RedirectAllowList;
import com.marschat.common.result.Result;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * IdP 登录页上下文（缺陷 A）——让**静态** login.html 能渲染「返回 &lt;应用&gt; 登录页」入口。
 *
 * <p>背景：应用跳 SSO → 302 /login.html，地址栏**不含** client_id/redirect_uri；
 * 原始 authorize 参数只存在于 session 的 SavedRequest 里（静态页读不到）。
 * 本端点把它解析为「该应用的独立登录页 URL」并返回。
 *
 * <p>契约（**只读、无副作用**）：成功 → {@code {code:200,data:{clientId,appName,returnTo}}}；
 * 任何解析不出/不在白名单/异常 → {@code {code:200,data:null}}（前端隐藏入口）。
 * **绝不抛错**：本端点异常不得影响登录流程。
 *
 * <p>安全：returnTo 出处是 **服务端 SavedRequest + 已注册客户端白名单**，
 * 且再经 {@link RedirectAllowList} 校验，不存在开放重定向。
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class LoginContextController {

    /**
     * HttpSessionRequestCache 的会话属性名。Spring Security 6.x 起该常量不再 public，
     * 故用字面量（属性名本身自 3.x 未变）作为兜底读取路径。
     */
    private static final String SAVED_REQUEST_ATTR = "SPRING_SECURITY_SAVED_REQUEST";
    /** 只有 OIDC 授权入口才需要"返回应用登录页"，其它 SavedRequest 一律忽略 */
    private static final String AUTHORIZE_SUFFIX = "/oauth2/authorize";
    /** SAS 回调路径后缀（用于反推应用部署前缀） */
    private static final String[] CALLBACK_SUFFIXES = {"/sso-callback.html", "/sso-callback", "/auth/callback"};

    private final RegisteredClientRepository registeredClientRepository;

    @GetMapping("/login-context")
    public Result<Map<String, Object>> loginContext(HttpServletRequest request, HttpServletResponse response) {
        try {
            SavedRequest saved = readSavedRequest(request, response);
            if (saved == null) {
                return Result.ok(null);
            }
            String redirectUrl = saved.getRedirectUrl();
            if (redirectUrl == null || !redirectUrl.contains(AUTHORIZE_SUFFIX)) {
                return Result.ok(null);
            }
            String clientId = param(saved, "client_id");
            if (clientId == null || clientId.isBlank()) {
                return Result.ok(null);
            }
            RegisteredClient client = registeredClientRepository.findByClientId(clientId);
            if (client == null) {
                return Result.ok(null);
            }
            String returnTo = resolveReturnTo(client, param(saved, "redirect_uri"));
            if (returnTo == null || !RedirectAllowList.isAllowed(returnTo)) {
                return Result.ok(null);
            }
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("clientId", client.getClientId());
            data.put("appName", client.getClientName());
            data.put("returnTo", returnTo);
            return Result.ok(data);
        } catch (Exception e) {
            // 降级：不显示返回入口；登录流程完全不受影响
            log.warn("登录页上下文解析失败（降级为不显示返回入口）: {}", e.getMessage());
            return Result.ok(null);
        }
    }

    /** 优先走 HttpSessionRequestCache（类型安全）；失败/为空再直读会话属性兜底。 */
    private static SavedRequest readSavedRequest(HttpServletRequest req, HttpServletResponse res) {
        try {
            SavedRequest sr = new HttpSessionRequestCache().getRequest(req, res);
            if (sr != null) {
                return sr;
            }
        } catch (Exception ignore) {
            // 落到下面的字面量读取
        }
        HttpSession session = req.getSession(false);
        Object attr = session == null ? null : session.getAttribute(SAVED_REQUEST_ATTR);
        return attr instanceof SavedRequest sr ? sr : null;
    }

    /** 取 SavedRequest 参数：优先 parameterMap，兜底解析 redirectUrl 的 query。 */
    private static String param(SavedRequest sr, String name) {
        try {
            Map<String, String[]> pm = sr.getParameterMap();
            if (pm != null) {
                String[] v = pm.get(name);
                if (v != null && v.length > 0 && v[0] != null && !v[0].isBlank()) {
                    return v[0];
                }
            }
        } catch (Exception ignore) {
            // 落兜底
        }
        return queryParam(sr.getRedirectUrl(), name);
    }

    /**
     * 由 SavedRequest 推导「应用独立登录页」：
     * ① redirect_uri 反推该应用部署前缀（/ops/sso-callback → /ops）；
     * ② 优先取该客户端 post-logout 白名单里「同 origin 且 path 以该前缀开头」的那条
     *    —— 按平台约定它就是应用登录页（portal→/portal/login、kbweb→/kb/login、
     *    kbops→/ops/login、inframon→/infra/login、activecode→/activecode/login.html）；
     * ③ 否则回落 `origin + 前缀 + /login`（仅当前缀至多一段，防 tokenhub 这类深路径误推）。
     */
    private static String resolveReturnTo(RegisteredClient client, String rawRedirectUri) {
        URI ru = parse(rawRedirectUri);
        if (ru == null || ru.getHost() == null) {
            return null;
        }
        String origin = originOf(ru);
        String prefix = stripCallbackSuffix(ru.getPath());
        if (prefix == null) {
            return null;
        }
        // ① 注册表优先（能拿到 activecode 的 .html 后缀等特例）
        //    注意：SAS 的 RegisteredClient#getPostLogoutRedirectUris() 返回 Set<String>（非 Set<URI>），
        //    故逐条解析后比较；命中即返回**原始登记串**，以保留 /login.html 等精确后缀。
        for (String candidate : client.getPostLogoutRedirectUris()) {
            URI cand = parse(candidate);
            if (cand != null
                    && origin.equals(originOf(cand))
                    && cand.getPath() != null
                    && cand.getPath().startsWith(prefix)) {
                return candidate;
            }
        }
        // ② 约定兜底：一次部署前缀（/kb、/ops、/infra、/portal…）或空前缀（cosmic）
        if (prefix.isEmpty() || prefix.indexOf('/', 1) < 0) {
            return origin + prefix + "/login";
        }
        return null;
    }

    private static String originOf(URI u) {
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase();
        String authority = u.getAuthority() == null ? "" : u.getAuthority().toLowerCase();
        return scheme + "://" + authority;
    }

    /** '/ops/sso-callback' → '/ops'；'/portal/auth/callback' → '/portal'；'/sso-callback' → ''；识别不出 → null */
    private static String stripCallbackSuffix(String path) {
        if (path == null) {
            return null;
        }
        for (String suffix : CALLBACK_SUFFIXES) {
            if (path.endsWith(suffix)) {
                return path.substring(0, path.length() - suffix.length());
            }
        }
        return null;
    }

    private static URI parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return URI.create(raw.trim());
        } catch (Exception e) {
            return null;
        }
    }

    private static String queryParam(String url, String name) {
        if (url == null) {
            return null;
        }
        int q = url.indexOf('?');
        if (q < 0) {
            return null;
        }
        for (String kv : url.substring(q + 1).split("&")) {
            int eq = kv.indexOf('=');
            if (eq > 0 && kv.substring(0, eq).equals(name)) {
                return URLDecoder.decode(kv.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }
}
