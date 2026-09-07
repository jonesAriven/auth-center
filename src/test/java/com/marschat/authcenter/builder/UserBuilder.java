package com.marschat.authcenter.builder;

import com.marschat.authcenter.entity.User;

import java.time.LocalDateTime;

/**
 * 用户测试数据工厂（SOP 2.5.3 Builder 模式）
 * <p>
 * 提供快速构造各种状态 User 实体的快捷方法。
 *
 * <pre>{@code
 *   User admin = UserBuilder.anAdminUser().withId(2L).build();
 * }</pre>
 */
public class UserBuilder {

    private Long id = 1L;
    private String username = "admin";
    private String password = "$2a$10$hashedPassword";
    private String email = "admin@kb.com";
    private String phone = "13800000000";
    private String wechatOpenid;
    private String avatar;
    private String nickname = "管理员";
    private Integer status = 1;
    private Integer deleted = 0;
    private LocalDateTime createdAt = LocalDateTime.now();
    private LocalDateTime updatedAt = LocalDateTime.now();

    private UserBuilder() {}

    /**
     * 默认合法用户
     */
    public static UserBuilder aUser() {
        return new UserBuilder();
    }

    /**
     * 管理员用户
     */
    public static UserBuilder anAdminUser() {
        return new UserBuilder()
                .withUsername("admin")
                .withNickname("系统管理员")
                .withStatus(1);
    }

    /**
     * 被禁用用户
     */
    public static UserBuilder aDisabledUser() {
        return new UserBuilder()
                .withUsername("disabled_user")
                .withNickname("已禁用用户")
                .withStatus(0);
    }

    public UserBuilder withId(Long id) {
        this.id = id;
        return this;
    }

    public UserBuilder withUsername(String username) {
        this.username = username;
        return this;
    }

    public UserBuilder withPassword(String password) {
        this.password = password;
        return this;
    }

    public UserBuilder withEmail(String email) {
        this.email = email;
        return this;
    }

    public UserBuilder withPhone(String phone) {
        this.phone = phone;
        return this;
    }

    public UserBuilder withWechatOpenid(String wechatOpenid) {
        this.wechatOpenid = wechatOpenid;
        return this;
    }

    public UserBuilder withAvatar(String avatar) {
        this.avatar = avatar;
        return this;
    }

    public UserBuilder withNickname(String nickname) {
        this.nickname = nickname;
        return this;
    }

    public UserBuilder withStatus(Integer status) {
        this.status = status;
        return this;
    }

    public UserBuilder withDeleted(Integer deleted) {
        this.deleted = deleted;
        return this;
    }

    public UserBuilder withCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
        return this;
    }

    public UserBuilder withUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
        return this;
    }

    public User build() {
        User user = new User();
        user.setId(id);
        user.setUsername(username);
        user.setPassword(password);
        user.setEmail(email);
        user.setPhone(phone);
        user.setWechatOpenid(wechatOpenid);
        user.setAvatar(avatar);
        user.setNickname(nickname);
        user.setStatus(status);
        user.setDeleted(deleted);
        user.setCreatedAt(createdAt);
        user.setUpdatedAt(updatedAt);
        return user;
    }
}
