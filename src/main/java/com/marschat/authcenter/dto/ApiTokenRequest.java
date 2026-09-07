package com.marschat.authcenter.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class ApiTokenRequest {

    @NotBlank(message = "Token名称不能为空")
    private String name;

    /** 权限范围，逗号分隔 */
    private String scope;

    /** 过期时间，null 表示永不过期。接受 yyyy-MM-dd HH:mm:ss 格式 */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime expireAt;
}
