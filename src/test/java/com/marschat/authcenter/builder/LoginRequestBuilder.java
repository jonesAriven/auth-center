package com.marschat.authcenter.builder;

import com.marschat.authcenter.dto.LoginRequest;

/**
 * 登录请求测试数据工厂（SOP 2.5.3 Builder 模式）
 */
public class LoginRequestBuilder {

    private String username = "admin";
    private String password = "admin123";

    private LoginRequestBuilder() {}

    /**
     * 默认合法登录请求（admin/admin123）
     */
    public static LoginRequestBuilder aValidLoginRequest() {
        return new LoginRequestBuilder();
    }

    /**
     * 错误密码的登录请求
     */
    public static LoginRequestBuilder aWrongPasswordRequest() {
        return new LoginRequestBuilder().withPassword("wrong_password");
    }

    /**
     * 不存在的用户登录请求
     */
    public static LoginRequestBuilder aNonExistentUserRequest() {
        return new LoginRequestBuilder().withUsername("non_existent_user").withPassword("any_password");
    }

    public LoginRequestBuilder withUsername(String username) {
        this.username = username;
        return this;
    }

    public LoginRequestBuilder withPassword(String password) {
        this.password = password;
        return this;
    }

    public LoginRequest build() {
        LoginRequest request = new LoginRequest();
        request.setUsername(username);
        request.setPassword(password);
        return request;
    }
}
