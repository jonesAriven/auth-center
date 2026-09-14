package com.marschat.authcenter.entity;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

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

    /**
     * 应用作用域查询时回填：该用户在本应用（client）下拥有的角色（[{id,code,name}]）。
     *
     * <p>非持久化字段——仅 {@code GET /admin/users?client=<id>} 会填充，
     * 供前端「本系统用户」列表直接展示「本系统角色」列，避免逐行再发请求。
     * 平台作用域查询不返回该字段（保持历史契约不变）。
     */
    @TableField(exist = false)
    private List<Map<String, Object>> appRoles;
}
