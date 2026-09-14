package com.marschat.authcenter.service;

import com.marschat.authcenter.entity.User;
import com.marschat.common.page.PageResult;

import java.util.List;

public interface UserService {

    User getProfile(Long userId);

    User updateProfile(Long userId, String nickname, String email, String phone, String avatar);

    void updatePassword(Long userId, String oldPassword, String newPassword);

    List<User> listAll();

    /** —— 统一用户管理（auth-center Phase 1，仅 ROLE_ADMIN）—— */

    PageResult<User> listForAdmin(String realmId, String keyword, int page, int size);

    /**
     * 应用作用域用户列表（Phase 8「本系统用户」）。
     *
     * <p>语义：只返回「与本应用有关」的用户，判据三者取或——
     * <ol>
     *   <li>在本应用（{@code sys_user_role.client_id = clientId}）有角色绑定；</li>
     *   <li>在本应用有账号映射认领（{@code app_account_mapping.client_id=clientId AND status=1 AND user_id 非空}）；</li>
     *   <li>全局角色是 {@code admin}/{@code superadmin}（管理员始终可见——
     *       保证首次配置时列表不为空、应用管理员能看到自己的账号）。</li>
     * </ol>
     * 每条记录回填 {@link User#getAppRoles()}（该用户在本应用的角色）。
     */
    PageResult<User> listForAdminScoped(String clientId, String realmId, String keyword, int page, int size);

    User createUser(String username, String password, String role, String nickname,
                    String email, String realmId, Long operatorId);

    User updateUser(Long userId, String role, Integer status, String nickname,
                    String email, Long operatorId);

    void deleteUser(Long userId, Long operatorId);

    void resetPassword(Long userId, String newPassword, Long operatorId);
}
