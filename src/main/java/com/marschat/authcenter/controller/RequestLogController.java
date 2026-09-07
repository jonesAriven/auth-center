package com.marschat.authcenter.controller;

import com.marschat.common.page.PageResult;
import com.marschat.common.result.Result;
import com.marschat.authcenter.entity.RequestLog;
import com.marschat.authcenter.service.RequestLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth/request-log")
@RequiredArgsConstructor
public class RequestLogController {

    private final RequestLogService requestLogService;

    @GetMapping("/list")
    public Result<PageResult<RequestLog>> list(
            @RequestParam(required = false) String traceId,
            @RequestParam(required = false) Long userId,
            @RequestParam(required = false) String httpMethod,
            @RequestParam(required = false) String uri,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String serviceName,
            @RequestParam(required = false) String startTime,
            @RequestParam(required = false) String endTime,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size) {
        return Result.ok(requestLogService.list(traceId, userId, httpMethod, uri, status, serviceName, startTime, endTime, page, size));
    }

    @GetMapping("/{id}")
    public Result<RequestLog> detail(@PathVariable Long id) {
        return Result.ok(requestLogService.getById(id));
    }
}
