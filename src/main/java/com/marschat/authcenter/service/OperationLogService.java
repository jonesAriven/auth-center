package com.marschat.authcenter.service;

import com.marschat.common.page.PageResult;
import com.marschat.authcenter.entity.OperationLog;

/**
 * 操作日志服务
 */
public interface OperationLogService {
    /**
     * 异步记录操作日志
     */
    void log(Long userId, String username, String action, String resourceType, Long resourceId, String detail, String ip);

    /**
     * 分页查询操作日志
     */
    PageResult<OperationLog> list(Long userId, String action, String resourceType, String startTime, String endTime, int page, int size);

    /**
     * 查询日志详情
     */
    OperationLog getById(Long id);
}
