package com.marschat.authcenter.controller;

import com.marschat.authcenter.service.AccountMappingService;
import com.marschat.authcenter.util.SecurityUtils;
import com.marschat.common.result.Result;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 账号映射管理端点（统一身份 ↔ 各系统本地账号）。
 *
 * <p>与 /admin/users、/admin/roles 同一鉴权面：链3 Bearer + {@code @PreAuthorize(ROLE_ADMIN)}
 * + CORS /admin/**。用于回答两个管理诉求：
 * <ul>
 *   <li><b>哪些账号有哪些系统的账号</b>：{@code GET /admin/mappings?client=X}（按系统视角）</li>
 *   <li><b>某个人在各系统的账号</b>：{@code GET /admin/users/{id}/mappings}（按人视角）</li>
 * </ul>
 * 另有手工绑定/解绑，处理自动认领未能覆盖的歧义场景。
 */
@Slf4j
@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminAccountMappingController {

    private final AccountMappingService accountMappingService;

    /** 映射列表（分页）。按应用 / 中心用户 / 关键字过滤。 */
    @GetMapping("/mappings")
    public Result<Map<String, Object>> list(@RequestParam(required = false) String client,
                                            @RequestParam(required = false) Long userId,
                                            @RequestParam(required = false) String keyword,
                                            @RequestParam(defaultValue = "1") int page,
                                            @RequestParam(defaultValue = "20") int size) {
        return Result.ok(accountMappingService.listMappings(client, userId, keyword, page, size));
    }

    /** 覆盖概览（每个应用 总/已认领/待绑定），管理界面顶部用。 */
    @GetMapping("/mappings/summary")
    public Result<?> summary() {
        return Result.ok(accountMappingService.summary());
    }

    /** 某中心统一用户在**各系统**的账号映射（按人视角聚合）。 */
    @GetMapping("/users/{userId}/mappings")
    public Result<?> byUser(@PathVariable long userId) {
        return Result.ok(accountMappingService.listByUser(userId));
    }

    /** 手工绑定：把某条应用本地账号认领到指定中心用户。body: {"userId": 148} */
    @PostMapping("/mappings/{mappingId}/bind")
    public Result<?> bind(@PathVariable long mappingId, @RequestBody BindRequest body) {
        if (body == null || body.getUserId() == null) {
            return Result.fail(400, "缺少 userId");
        }
        try {
            return Result.ok(Map.of("bound",
                    accountMappingService.bindMapping(mappingId, body.getUserId())));
        } catch (IllegalArgumentException e) {
            return Result.fail(400, e.getMessage());
        }
    }

    /** 解绑：清空中心用户关联，回到「待绑定」。 */
    @PostMapping("/mappings/{mappingId}/unbind")
    public Result<?> unbind(@PathVariable long mappingId) {
        log.info("账号映射解绑: mappingId={} operator={}", mappingId, safeOperator());
        return Result.ok(Map.of("unbound", accountMappingService.unbindMapping(mappingId)));
    }

    private Long safeOperator() {
        try {
            return SecurityUtils.getCurrentUserId();
        } catch (Exception e) {
            return null;
        }
    }

    @Data
    public static class BindRequest {
        private Long userId;
    }
}
