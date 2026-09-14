package com.marschat.authcenter.controller;

import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.service.UserService;
import com.marschat.authcenter.util.SecurityUtils;
import com.marschat.common.page.PageResult;
import com.marschat.common.result.Result;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 统一用户管理（auth-center Phase 1）。
 * 仅 ROLE_ADMIN 可访问（JwtAuthenticationFilter 已从 user.role 注入 authority）。
 */
@RestController
@RequestMapping("/admin/users")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminUserController {

    private final UserService userService;

    /**
     * 用户列表（含禁用），支持 realm 过滤、关键字搜索（username/email/nickname）、分页。
     *
     * <p><b>双作用域（Phase 8）</b>——同一端点、两种语义，由 {@code client} 参数切换：
     * <ul>
     *   <li><b>不传 {@code client}</b> → <b>平台作用域</b>：全平台统一身份。
     *       供中心侧「统一认证中心 → 统一用户」使用（宿主 portal）。</li>
     *   <li><b>传 {@code client}</b> → <b>应用作用域</b>：只返回「与本应用有关」的用户
     *       （在本应用有角色绑定 / 有本应用账号映射认领 / 是管理员）。
     *       供各应用「本系统用户」使用，并回填每条记录的 {@code appRoles}。</li>
     * </ul>
     * 这样「应用侧只看本系统、中心侧看全平台」由**服务端强制**，而不是靠前端自觉。
     */
    @GetMapping
    public Result<PageResult<User>> list(
            @RequestParam(required = false) String realmId,
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String client,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size) {
        if (client != null && !client.isBlank()) {
            return Result.ok(userService.listForAdminScoped(client.trim(), realmId, keyword, page, size));
        }
        return Result.ok(userService.listForAdmin(realmId, keyword, page, size));
    }

    @PostMapping
    public Result<User> create(@RequestBody CreateUserRequest request) {
        Long operatorId = SecurityUtils.getCurrentUserId();
        return Result.ok(userService.createUser(request.getUsername(), request.getPassword(),
                request.getRole(), request.getNickname(), request.getEmail(),
                request.getRealmId(), operatorId));
    }

    @PutMapping("/{userId}")
    public Result<User> update(@PathVariable Long userId, @RequestBody UpdateUserRequest request) {
        Long operatorId = SecurityUtils.getCurrentUserId();
        return Result.ok(userService.updateUser(userId, request.getRole(), request.getStatus(),
                request.getNickname(), request.getEmail(), operatorId));
    }

    @DeleteMapping("/{userId}")
    public Result<Void> delete(@PathVariable Long userId) {
        userService.deleteUser(userId, SecurityUtils.getCurrentUserId());
        return Result.ok();
    }

    @PutMapping("/{userId}/password")
    public Result<Void> resetPassword(@PathVariable Long userId, @RequestBody ResetPasswordRequest request) {
        userService.resetPassword(userId, request.getNewPassword(), SecurityUtils.getCurrentUserId());
        return Result.ok();
    }

    @Data
    public static class CreateUserRequest {
        private String username;
        private String password;
        private String role;
        private String nickname;
        private String email;
        private String realmId;
    }

    @Data
    public static class UpdateUserRequest {
        private String role;
        private Integer status;
        private String nickname;
        private String email;
    }

    @Data
    public static class ResetPasswordRequest {
        private String newPassword;
    }
}
