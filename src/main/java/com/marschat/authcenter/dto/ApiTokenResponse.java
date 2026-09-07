package com.marschat.authcenter.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * API Token 创建后的返回对象
 * <p>
 * token 明文仅在创建时返回一次，后续查询只能看到前缀。
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApiTokenResponse {

    private Long id;
    private String name;
    /** 明文 token，仅创建时返回 */
    private String token;
    private String tokenPrefix;
    private String scope;
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime expireAt;
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createdAt;
}
