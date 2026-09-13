package com.marschat.authcenter.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 应用账号映射（统一身份 ↔ 各系统本地账号）。
 *
 * <p>背景：平台初衷是「用户统一管理 + 账号映射」。历史实现中各应用各自维护账号库
 * （portal.sys_user / activecode.admin_user / cosmic.users / infra 配置式管理员），
 * 中心侧只建了 {@code user_identity}（provider=email/phone/wechat），**无法回答
 * 「某个人在某个系统里是哪个账号」**。
 *
 * <p>本表把「应用侧本地账号」显式登记到中心：
 * <ul>
 *   <li>{@code client_id + local_account} 唯一 —— 一个应用内一个本地账号一行；</li>
 *   <li>{@code user_id} 指向中心统一用户（NULL = 未认领/未绑定）；</li>
 *   <li>{@code source}：{@code report}=应用上报未认领 / {@code auto}=按 username|email 自动认领 /
 *       {@code manual}=管理员手工绑定；</li>
 *   <li>{@code status}：1=有效 0=失效（本次上报未出现的旧账号，全量覆盖语义）。</li>
 * </ul>
 */
@Data
@TableName("app_account_mapping")
public class AppAccountMapping {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 中心统一用户 ID（NULL = 尚未认领到统一身份） */
    private Long userId;

    /** 应用标识（OIDC client_id） */
    private String clientId;

    /** 应用侧本地账号标识（用户名 / 登录名 / 本地主键） */
    private String localAccount;

    /** 应用侧显示名（昵称/备注，便于人工核对） */
    private String localDisplayName;

    /** 映射来源：report=应用上报 / auto=自动认领 / manual=手工绑定 */
    private String source;

    /** 1=有效 0=失效 */
    private Integer status;

    /** 认领/绑定时间（未认领为 NULL） */
    private LocalDateTime linkedAt;

    /** 最近一次被应用上报的时间 */
    private LocalDateTime lastSeenAt;

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;

    @TableField(fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updatedAt;
}
