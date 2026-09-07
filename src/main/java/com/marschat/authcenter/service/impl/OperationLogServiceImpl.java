package com.marschat.authcenter.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.marschat.common.page.PageResult;
import com.marschat.authcenter.entity.OperationLog;
import com.marschat.authcenter.mapper.OperationLogMapper;
import com.marschat.authcenter.service.OperationLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;

/**
 * 操作日志服务实现
 * 从 kb-ops 迁移而来，保留原有 @Async 异步写入能力
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OperationLogServiceImpl implements OperationLogService {

    private final OperationLogMapper logMapper;

    @Async
    @Override
    public void log(Long userId, String username, String action, String resourceType, Long resourceId, String detail, String ip) {
        OperationLog entity = new OperationLog();
        entity.setUserId(userId);
        entity.setUsername(username);
        entity.setAction(action);
        entity.setResourceType(resourceType);
        entity.setResourceId(resourceId);
        entity.setDetail(detail);
        entity.setIp(ip);
        try {
            logMapper.insert(entity);
        } catch (Exception e) {
            log.error("[操作日志] 记录失败: userId={}, action={}", userId, action, e);
        }
    }

    @Override
    public PageResult<OperationLog> list(Long userId, String action, String resourceType, String startTime, String endTime, int page, int size) {
        LambdaQueryWrapper<OperationLog> wrapper = new LambdaQueryWrapper<>();
        if (userId != null) {
            wrapper.eq(OperationLog::getUserId, userId);
        }
        if (StringUtils.hasText(action)) {
            wrapper.eq(OperationLog::getAction, action);
        }
        if (StringUtils.hasText(resourceType)) {
            wrapper.eq(OperationLog::getResourceType, resourceType);
        }
        if (StringUtils.hasText(startTime)) {
            wrapper.ge(OperationLog::getCreatedAt, LocalDateTime.parse(startTime));
        }
        if (StringUtils.hasText(endTime)) {
            wrapper.le(OperationLog::getCreatedAt, LocalDateTime.parse(endTime));
        }
        wrapper.orderByDesc(OperationLog::getCreatedAt);
        Page<OperationLog> p = logMapper.selectPage(new Page<>(page, size), wrapper);
        return PageResult.of(p.getRecords(), p.getTotal(), page, size);
    }

    @Override
    public OperationLog getById(Long id) {
        return logMapper.selectById(id);
    }
}
