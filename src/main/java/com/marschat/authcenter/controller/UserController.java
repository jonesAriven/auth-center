package com.marschat.authcenter.controller;

import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.service.AccountMappingService;
import com.marschat.authcenter.service.UserService;
import com.marschat.authcenter.util.SecurityUtils;
import com.marschat.common.result.Result;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final AccountMappingService accountMappingService;

    @GetMapping("/profile")
    public Result<User> getProfile() {
        return Result.ok(userService.getProfile(SecurityUtils.getCurrentUserId()));
    }

    @GetMapping("/list")
    public Result<List<User>> list() {
        return Result.ok(userService.listAll());
    }

    @PutMapping("/profile")
    public Result<User> updateProfile(@RequestBody UpdateProfileRequest request) {
        return Result.ok(userService.updateProfile(SecurityUtils.getCurrentUserId(),
                request.getNickname(), request.getEmail(), request.getPhone(), request.getAvatar()));
    }

    @PutMapping("/password")
    public Result<Void> updatePassword(@RequestBody UpdatePasswordRequest request) {
        userService.updatePassword(SecurityUtils.getCurrentUserId(),
                request.getOldPassword(), request.getNewPassword());
        return Result.ok();
    }

    /**
     * 账号映射 · 自助查询（登录径闭环，ADR-2026-09-10 §33.8 拍板 A）。
     *
     * <p>应用侧登录时若本地账号名与中心账号名不一致，原本只能 403 引导绑定；
     * 现在应用可在 403 之前以**用户本人 access_token**（RS256，/user/** 已在 authenticated 链内）
     * 调本端点查 {@code app_account_mapping} 中 (user_id, client_id) 的绑定记录，
     * 命中则直接以绑定的 local_account 身份登录。
     *
     * <p>只读复用 {@link AccountMappingService#listByUser}（status=1），无新依赖、可降级
     * （应用侧对查询失败的处理是回落原 403 分支，不放开）。
     *
     * @param clientId 可选；传则只返回该应用的绑定行（client_id + local_account 唯一，至多 1 行）
     */
    @GetMapping("/mapping")
    public Result<List<Map<String, Object>>> myMapping(
            @RequestParam(value = "clientId", required = false) String clientId) {
        List<Map<String, Object>> mappings = accountMappingService.listByUser(SecurityUtils.getCurrentUserId());
        if (clientId != null && !clientId.isBlank()) {
            mappings = mappings.stream()
                    .filter(m -> clientId.equals(m.get("client_id")))
                    .toList();
        }
        return Result.ok(mappings);
    }

    @Data
    public static class UpdateProfileRequest {
        private String nickname;
        private String email;
        private String phone;
        private String avatar;
    }

    @Data
    public static class UpdatePasswordRequest {
        private String oldPassword;
        private String newPassword;
    }
}
