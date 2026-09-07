package com.marschat.authcenter.entity;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@TableName("user")
public class User {

    @TableId(type = IdType.AUTO)
    private Long id;

    private String username;

    private String password;

    private String email;

    private String phone;

    private String wechatOpenid;

    private String avatar;

    private String nickname;

    private Integer status;

    /** 账号所属 realm（账号池）：同 realm 内应用可 SSO，跨 realm 隔离 */
    private String realmId;

    /** 角色：admin / user */
    private String role;

    @TableLogic
    private Integer deleted;

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;

    @TableField(fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updatedAt;
}
