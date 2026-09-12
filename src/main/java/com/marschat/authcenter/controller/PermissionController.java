package com.marschat.authcenter.controller;

import com.marschat.authcenter.service.PermissionService;
import com.marschat.common.result.Result;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 权限下发（Phase 2 · unified-auth 方案 §3.3）。
 *
 * <p>登录后前端/服务端拉取本应用权限集合：路由守卫拦截 + 菜单按集合渲染 + @RequirePermission。
 * 鉴权走链 3（Bearer，JwtAuthenticationFilter 已设 principal=uid）；
 * CORS 由 adminApiCorsConfigurationSource 注册（credentials 模式回显 Origin）。
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class PermissionController {

    private final PermissionService permissionService;

    @GetMapping("/permissions")
    public Result<Map<String, Object>> permissions(@RequestParam(name = "client") String client,
                                                   jakarta.servlet.http.HttpServletRequest request) {
        Object uidAttr = request.getAttribute("userId");
        if (uidAttr == null) {
            return Result.fail(401, "未认证");
        }
        long userId = Long.parseLong(String.valueOf(uidAttr));
        return Result.ok(permissionService.computeForUser(userId, client));
    }
}
