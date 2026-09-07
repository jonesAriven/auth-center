package com.marschat.authcenter.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.marschat.common.page.PageResult;
import com.marschat.authcenter.entity.RequestLog;
import com.marschat.authcenter.mapper.RequestLogMapper;
import com.marschat.authcenter.service.RequestLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class RequestLogServiceImpl implements RequestLogService {

    private final RequestLogMapper requestLogMapper;

    @Async
    @Override
    public void log(RequestLog requestLog) {
        try {
            requestLogMapper.insert(requestLog);
        } catch (Exception e) {
            log.error("[请求日志] 记录失败: traceId={}, uri={}", requestLog.getTraceId(), requestLog.getRequestUri(), e);
        }
    }

    @Override
    public PageResult<RequestLog> list(String traceId, Long userId, String httpMethod, String uri,
                                       String status, String serviceName, String startTime, String endTime,
                                       int page, int size) {
        LambdaQueryWrapper<RequestLog> wrapper = new LambdaQueryWrapper<>();
        if (StringUtils.hasText(traceId)) {
            wrapper.like(RequestLog::getTraceId, traceId);
        }
        if (userId != null) {
            wrapper.eq(RequestLog::getUserId, userId);
        }
        if (StringUtils.hasText(httpMethod)) {
            wrapper.eq(RequestLog::getHttpMethod, httpMethod);
        }
        if (StringUtils.hasText(uri)) {
            wrapper.like(RequestLog::getRequestUri, uri);
        }
        if (StringUtils.hasText(status)) {
            wrapper.eq(RequestLog::getStatus, status);
        }
        if (StringUtils.hasText(serviceName)) {
            wrapper.eq(RequestLog::getServiceName, serviceName);
        }
        if (StringUtils.hasText(startTime)) {
            wrapper.ge(RequestLog::getCreatedAt, LocalDateTime.parse(startTime));
        }
        if (StringUtils.hasText(endTime)) {
            wrapper.le(RequestLog::getCreatedAt, LocalDateTime.parse(endTime));
        }
        wrapper.orderByDesc(RequestLog::getCreatedAt);
        Page<RequestLog> p = requestLogMapper.selectPage(new Page<>(page, size), wrapper);
        return PageResult.of(p.getRecords(), p.getTotal(), page, size);
    }

    @Override
    public RequestLog getById(Long id) {
        return requestLogMapper.selectById(id);
    }
}
