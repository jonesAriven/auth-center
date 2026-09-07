package com.marschat.authcenter.entity;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@TableName("jwt_blacklist")
public class JwtBlacklist {

    @TableId(type = IdType.AUTO)
    private Long id;

    private String token;

    private LocalDateTime expireAt;

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;
}
