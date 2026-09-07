package com.marschat.authcenter.controller;

import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.service.UserService;
import com.marschat.authcenter.util.SecurityUtils;
import com.marschat.common.result.Result;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

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
