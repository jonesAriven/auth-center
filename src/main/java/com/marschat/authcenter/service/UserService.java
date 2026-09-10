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

    User createUser(String username, String password, String role, String nickname,
                    String email, String realmId, Long operatorId);

    User updateUser(Long userId, String role, Integer status, String nickname,
                    String email, Long operatorId);

    void deleteUser(Long userId, Long operatorId);

    void resetPassword(Long userId, String newPassword, Long operatorId);
}
