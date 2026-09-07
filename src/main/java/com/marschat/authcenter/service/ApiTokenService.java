package com.marschat.authcenter.service;

import com.marschat.authcenter.dto.ApiTokenRequest;
import com.marschat.authcenter.dto.ApiTokenResponse;
import com.marschat.authcenter.entity.ApiToken;
import com.marschat.common.page.PageResult;

import java.util.List;

public interface ApiTokenService {

    /**
     * 创建 API Token，返回明文 token（仅此一次）
     */
    ApiTokenResponse create(Long userId, ApiTokenRequest request);

    /**
     * 分页查询当前用户的 API Token 列表
     */
    PageResult<ApiToken> list(Long userId, int page, int size);

    /**
     * 删除 API Token（逻辑删除）
     */
    void delete(Long userId, Long tokenId);

    /**
     * 禁用/启用 API Token
     */
    void toggleStatus(Long userId, Long tokenId);

    /**
     * 验证 API Token 明文，返回对应的 token 记录。
     * 供其他服务通过 Feign 调用验证。
     */
    ApiToken verify(String rawToken);

    /**
     * 查询用户所有有效 Token
     */
    List<ApiToken> listByUser(Long userId);
}
