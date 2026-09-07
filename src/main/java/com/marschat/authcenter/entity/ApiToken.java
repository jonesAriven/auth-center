package com.marschat.authcenter.entity;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * API Token 实体
 * <p>
 * 用于外部系统或运维工具通过 API Token 访问服务，
 * 替代用户登录的 JWT 方式。Token 明文仅创建时返回一次，数据库存储加密后的值。
 */
@Data
@TableName("ops_api_token")
public class ApiToken {

    @TableId(type = IdType.AUTO)
    private Long id;

    private Long userId;

    /** Token 名称（便于用户识别） */
    private String name;

    /** 加密后的 Token（AES-256-GCM） */
    private String tokenEncrypted;

    /** Token 前缀（用于展示，如 kb_abc1****） */
    private String tokenPrefix;

    /** 权限范围，逗号分隔，如 ops:read,ops:write */
    private String scope;

    /** 0=启用, 1=禁用 */
    private Integer status;

    private LocalDateTime expireAt;

    private LocalDateTime lastUsedAt;

    @TableLogic
    private Integer deleted;

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;

    @TableField(fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updatedAt;
}
