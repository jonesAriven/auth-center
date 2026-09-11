package com.marschat.authcenter.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 授权拒绝的语义化映射（403）。
 *
 * common-core 的 GlobalExceptionHandler 只兜底 Exception.class → 500「服务内部错误」，
 * 而 /admin/** 的方法级 @PreAuthorize 拒绝普通用户时抛 AccessDeniedException，
 * 被兜成 500 并打 ERROR 日志污染告警（2026-09-12 实测）。
 * 本 advice 以更高优先级精确捕获，映射为 403 + WARN。
 */
@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice
public class AccessDeniedAdvice {

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDenied(AccessDeniedException e) {
        log.warn("访问被拒绝: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body("{\"code\":403,\"message\":\"当前账号无权限执行此操作\",\"data\":null}");
    }
}
