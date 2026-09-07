package com.marschat.authcenter.service;

import com.marschat.common.page.PageResult;
import com.marschat.authcenter.entity.ErrorLog;

public interface ErrorLogService {
    void log(Long userId, String username, String level, String source, String message, String stackTrace, String url, String ip);

    PageResult<ErrorLog> list(Long userId, String level, String source, String startTime, String endTime, int page, int size);

    ErrorLog getById(Long id);
}
