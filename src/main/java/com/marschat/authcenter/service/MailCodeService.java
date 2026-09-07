package com.marschat.authcenter.service;

import com.marschat.common.exception.BusinessException;

/**
 * 邮箱验证码一次性凭证服务（M7）。
 * <p>
 * 基于 Redis 管理验证码的生命周期：
 * <ul>
 *   <li>验证码：{@code auth:mail:code:{bizType}:{target}}，TTL 5 分钟，校验成功即删除（一次性）</li>
 *   <li>限频：{@code auth:mail:ratelimit:{bizType}:{target}}，TTL 60 秒，防止 60 秒内重复发送</li>
 *   <li>错误计数：{@code auth:mail:fail:{bizType}:{target}}，15 分钟内连续错误计数</li>
 *   <li>锁定：{@code auth:mail:lock:{bizType}:{target}}，连续错误 5 次锁定 15 分钟</li>
 * </ul>
 */
public interface MailCodeService {

    /** 生成并写入验证码，受 60 秒限频约束；返回生成的 6 位码（供发送邮件使用） */
    String issue(String bizType, String target);

    /** 校验验证码：成功则删除凭证并返回；失败/过期/锁定则抛异常 */
    void verify(String bizType, String target, String inputCode);
}
