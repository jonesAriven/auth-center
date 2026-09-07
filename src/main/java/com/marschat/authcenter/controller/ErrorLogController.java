package com.marschat.authcenter.controller;

import com.marschat.common.page.PageResult;
import com.marschat.common.result.Result;
import com.marschat.authcenter.entity.ErrorLog;
import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.mapper.UserMapper;
import com.marschat.authcenter.service.ErrorLogService;
import com.marschat.authcenter.util.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth/error-log")
@RequiredArgsConstructor
public class ErrorLogController {

    private final ErrorLogService errorLogService;
    private final UserMapper userMapper;

    @PostMapping("/report")
    public Result<Void> report(@RequestBody ErrorLogReportRequest request, HttpServletRequest httpRequest) {
        Long userId = null;
        String username = null;
        try {
            userId = SecurityUtils.getCurrentUserId();
            User user = userMapper.selectById(userId);
            if (user != null) {
                username = user.getUsername();
            }
        } catch (Exception ignored) {
        }
        String ip = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        errorLogService.log(userId, username, request.getLevel(), request.getSource(),
                request.getMessage(), request.getStackTrace(), request.getUrl(), ip);
        return Result.ok();
    }

    @GetMapping("/list")
    public Result<PageResult<ErrorLog>> list(
            @RequestParam(required = false) Long userId,
            @RequestParam(required = false) String level,
            @RequestParam(required = false) String source,
            @RequestParam(required = false) String startTime,
            @RequestParam(required = false) String endTime,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size) {
        return Result.ok(errorLogService.list(userId, level, source, startTime, endTime, page, size));
    }

    @GetMapping("/{id}")
    public Result<ErrorLog> detail(@PathVariable Long id) {
        return Result.ok(errorLogService.getById(id));
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }

    @Data
    public static class ErrorLogReportRequest {
        private String level;
        private String source;
        private String message;
        private String stackTrace;
        private String url;
    }
}
