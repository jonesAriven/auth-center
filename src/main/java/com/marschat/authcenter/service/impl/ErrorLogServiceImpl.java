package com.marschat.authcenter.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.marschat.common.page.PageResult;
import com.marschat.authcenter.entity.ErrorLog;
import com.marschat.authcenter.mapper.ErrorLogMapper;
import com.marschat.authcenter.service.ErrorLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class ErrorLogServiceImpl implements ErrorLogService {

    private final ErrorLogMapper errorLogMapper;

    @Async
    @Override
    public void log(Long userId, String username, String level, String source, String message, String stackTrace, String url, String ip) {
        ErrorLog entity = new ErrorLog();
        entity.setUserId(userId);
        entity.setUsername(username);
        entity.setLevel(level);
        entity.setSource(source);
        entity.setMessage(message);
        entity.setStackTrace(stackTrace);
        entity.setUrl(url);
        entity.setIp(ip);
        try {
            errorLogMapper.insert(entity);
        } catch (Exception e) {
            log.error("[错误日志] 记录失败: userId={}, level={}, message={}", userId, level, message, e);
        }
    }

    @Override
    public PageResult<ErrorLog> list(Long userId, String level, String source, String startTime, String endTime, int page, int size) {
        LambdaQueryWrapper<ErrorLog> wrapper = new LambdaQueryWrapper<>();
        if (userId != null) {
            wrapper.eq(ErrorLog::getUserId, userId);
        }
        if (StringUtils.hasText(level)) {
            wrapper.eq(ErrorLog::getLevel, level);
        }
        if (StringUtils.hasText(source)) {
            wrapper.eq(ErrorLog::getSource, source);
        }
        if (StringUtils.hasText(startTime)) {
            wrapper.ge(ErrorLog::getCreatedAt, LocalDateTime.parse(startTime));
        }
        if (StringUtils.hasText(endTime)) {
            wrapper.le(ErrorLog::getCreatedAt, LocalDateTime.parse(endTime));
        }
        wrapper.orderByDesc(ErrorLog::getCreatedAt);
        Page<ErrorLog> p = errorLogMapper.selectPage(new Page<>(page, size), wrapper);
        return PageResult.of(p.getRecords(), p.getTotal(), page, size);
    }

    @Override
    public ErrorLog getById(Long id) {
        return errorLogMapper.selectById(id);
    }
}
