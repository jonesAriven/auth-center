package com.marschat.authcenter.service;

import com.marschat.common.page.PageResult;
import com.marschat.authcenter.entity.RequestLog;

public interface RequestLogService {
    void log(RequestLog requestLog);

    PageResult<RequestLog> list(String traceId, Long userId, String httpMethod, String uri,
                                String status, String serviceName, String startTime, String endTime,
                                int page, int size);

    RequestLog getById(Long id);
}
