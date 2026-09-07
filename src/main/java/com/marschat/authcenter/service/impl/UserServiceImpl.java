package com.marschat.authcenter.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.mapper.UserMapper;
import com.marschat.authcenter.service.UserService;
import com.marschat.common.exception.BusinessException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public User getProfile(Long userId) {
        User user = userMapper.selectById(userId);
        if (user == null) {
            throw new BusinessException("用户不存在");
        }
        user.setPassword(null);
        return user;
    }

    @Override
    public User updateProfile(Long userId, String nickname, String email, String phone, String avatar) {
        User user = userMapper.selectById(userId);
        if (user == null) {
            throw new BusinessException("用户不存在");
        }

        if (phone != null && !phone.equals(user.getPhone())) {
            User existPhone = userMapper.selectOne(
                    new LambdaQueryWrapper<User>().eq(User::getPhone, phone));
            if (existPhone != null) {
                throw new BusinessException("手机号已被使用");
            }
            user.setPhone(phone);
        }

        if (nickname != null) user.setNickname(nickname);
        if (email != null) user.setEmail(email);
        if (avatar != null) user.setAvatar(avatar);

        userMapper.updateById(user);
        user.setPassword(null);
        return user;
    }

    @Override
    public void updatePassword(Long userId, String oldPassword, String newPassword) {
        User user = userMapper.selectById(userId);
        if (user == null) {
            throw new BusinessException("用户不存在");
        }
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new BusinessException("原密码错误");
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        userMapper.updateById(user);
    }

    @Override
    public List<User> listAll() {
        List<User> users = userMapper.selectList(
                new LambdaQueryWrapper<User>().eq(User::getStatus, 1));
        users.forEach(u -> u.setPassword(null));
        return users;
    }

    @Override
    public List<User> listForAdmin(String realmId) {
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<User>()
                .orderByDesc(User::getCreatedAt);
        if (realmId != null && !realmId.isBlank()) {
            wrapper.eq(User::getRealmId, realmId);
        }
        List<User> users = userMapper.selectList(wrapper);
        users.forEach(u -> u.setPassword(null));
        return users;
    }

    @Override
    public User createUser(String username, String password, String role, String nickname,
                           String email, String realmId, Long operatorId) {
        if (username == null || !username.matches("^[a-zA-Z0-9_.-]{2,50}$")) {
            throw new BusinessException("用户名只能包含字母数字_.-，长度2-50");
        }
        if (password == null || password.length() < 6) {
            throw new BusinessException("密码长度至少6位");
        }
        String normalizedRole = normalizeRole(role);
        String normalizedRealm = (realmId == null || realmId.isBlank()) ? "kb" : realmId.trim();

        Long exist = userMapper.selectCount(new LambdaQueryWrapper<User>().eq(User::getUsername, username));
        if (exist != null && exist > 0) {
            throw new BusinessException("用户名已存在");
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(normalizedRole);
        user.setRealmId(normalizedRealm);
        user.setNickname(nickname);
        user.setEmail(email);
        user.setStatus(1);
        userMapper.insert(user);
        user.setPassword(null);
        return user;
    }

    @Override
    public User updateUser(Long userId, String role, Integer status, String nickname,
                           String email, Long operatorId) {
        User user = userMapper.selectById(userId);
        if (user == null) {
            throw new BusinessException("用户不存在");
        }
        // 边界保护：不能把自己降级或禁用（防误操作锁死在管理界面外）
        if (userId.equals(operatorId)) {
            if (role != null && !"admin".equals(normalizeRole(role))) {
                throw new BusinessException("不能修改自己的角色");
            }
            if (status != null && status == 0) {
                throw new BusinessException("不能禁用自己");
            }
        }
        if (role != null) {
            user.setRole(normalizeRole(role));
        }
        if (status != null) {
            user.setStatus(status);
        }
        if (nickname != null) {
            user.setNickname(nickname);
        }
        if (email != null) {
            user.setEmail(email);
        }
        userMapper.updateById(user);
        user.setPassword(null);
        return user;
    }

    @Override
    public void deleteUser(Long userId, Long operatorId) {
        if (userId.equals(operatorId)) {
            throw new BusinessException("不能删除自己");
        }
        User user = userMapper.selectById(userId);
        if (user == null) {
            throw new BusinessException("用户不存在");
        }
        // 边界保护：保护最后一个管理员
        if ("admin".equals(user.getRole())) {
            Long adminCount = userMapper.selectCount(new LambdaQueryWrapper<User>()
                    .eq(User::getRole, "admin").eq(User::getStatus, 1));
            if (adminCount != null && adminCount <= 1) {
                throw new BusinessException("系统至少保留一个管理员，禁止删除");
            }
        }
        userMapper.deleteById(userId);
    }

    @Override
    public void resetPassword(Long userId, String newPassword, Long operatorId) {
        if (newPassword == null || newPassword.length() < 6) {
            throw new BusinessException("密码长度至少6位");
        }
        User user = userMapper.selectById(userId);
        if (user == null) {
            throw new BusinessException("用户不存在");
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        userMapper.updateById(user);
    }

    private String normalizeRole(String role) {
        if (role == null || role.isBlank()) {
            return "user";
        }
        String r = role.trim().toLowerCase();
        if (!"admin".equals(r) && !"user".equals(r)) {
            throw new BusinessException("角色只允许 admin/user");
        }
        return r;
    }
}
