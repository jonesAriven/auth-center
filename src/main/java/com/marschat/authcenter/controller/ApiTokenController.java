package com.marschat.authcenter.controller;

import com.marschat.authcenter.dto.ApiTokenRequest;
import com.marschat.authcenter.dto.ApiTokenResponse;
import com.marschat.authcenter.entity.ApiToken;
import com.marschat.authcenter.service.ApiTokenService;
import com.marschat.authcenter.util.SecurityUtils;
import com.marschat.common.page.PageResult;
import com.marschat.common.result.Result;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

/**
 * API Token 管理 Controller
 * <p>
 * 提供对 API Token 的 CRUD 操作，以及供其他服务调用的 Token 验证接口。
 */
@RestController
@RequestMapping("/token")
@RequiredArgsConstructor
public class ApiTokenController {

    private final ApiTokenService apiTokenService;

    /**
     * 创建 API Token
     * <p>
     * 明文 token 仅在此接口返回一次，后续无法再次获取。
     */
    @PostMapping
    public Result<ApiTokenResponse> create(@Valid @RequestBody ApiTokenRequest request) {
        return Result.ok(apiTokenService.create(SecurityUtils.getCurrentUserId(), request));
    }

    /**
     * 分页查询当前用户的 API Token 列表
     */
    @GetMapping
    public Result<PageResult<ApiToken>> list(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size) {
        return Result.ok(apiTokenService.list(SecurityUtils.getCurrentUserId(), page, size));
    }

    /**
     * 删除 API Token
     */
    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        apiTokenService.delete(SecurityUtils.getCurrentUserId(), id);
        return Result.ok();
    }

    /**
     * 启用/禁用 API Token
     */
    @PutMapping("/{id}/toggle")
    public Result<Void> toggleStatus(@PathVariable Long id) {
        apiTokenService.toggleStatus(SecurityUtils.getCurrentUserId(), id);
        return Result.ok();
    }

    /**
     * 验证 API Token（供其他服务通过 Feign 调用）
     * <p>
     * 此接口无需 JWT 认证（在 SecurityConfig 中 permitAll）。
     */
    @PostMapping("/verify")
    public Result<ApiToken> verify(@RequestBody VerifyRequest request) {
        return Result.ok(apiTokenService.verify(request.getToken()));
    }

    @lombok.Data
    public static class VerifyRequest {
        private String token;
    }
}
