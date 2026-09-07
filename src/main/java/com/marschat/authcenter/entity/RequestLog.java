package com.marschat.authcenter.entity;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@TableName("sys_request_log")
public class RequestLog {
    @TableId(type = IdType.AUTO)
    private Long id;

    private String traceId;

    private Long userId;

    private String username;

    private String httpMethod;

    private String requestUri;

    private String controllerMethod;

    private String requestArgs;

    private String responseResult;

    private Long costMs;

    private String status;

    private String exception;

    private String ip;

    private String userAgent;

    private String serviceName;

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;
}
