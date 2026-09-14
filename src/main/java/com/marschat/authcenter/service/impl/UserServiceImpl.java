package com.marschat.authcenter.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.marschat.authcenter.entity.RefreshToken;
import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.mapper.RefreshTokenMapper;
import com.marschat.authcenter.mapper.UserMapper;
import com.marschat.authcenter.service.OperationLogService;
import com.marschat.authcenter.service.TokenVersionService;
import com.marschat.authcenter.service.UserService;
import com.marschat.common.exception.BusinessException;
import com.marschat.common.page.PageResult;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private static final String ROLE_SUPERADMIN = "superadmin";

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenMapper refreshTokenMapper;
    private final OperationLogService operationLogService;
    private final TokenVersionService tokenVersionService;
    private final JdbcTemplate jdbcTemplate;

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
    public PageResult<User> listForAdmin(String realmId, String keyword, int page, int size) {
        Page<User> pageObj = new Page<>(page, size);
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<User>()
                .orderByDesc(User::getCreatedAt);
        if (realmId != null && !realmId.isBlank()) {
            wrapper.eq(User::getRealmId, realmId);
        }
        if (keyword != null && !keyword.isBlank()) {
            wrapper.and(q -> q.like(User::getUsername, keyword)
                    .or().like(User::getEmail, keyword)
                    .or().like(User::getNickname, keyword));
        }
        Page<User> result = userMapper.selectPage(pageObj, wrapper);
        result.getRecords().forEach(u -> u.setPassword(null));
        return PageResult.of(result.getRecords(), result.getTotal(), page, size);
    }

    /**
     * 应用作用域列表（Phase 8「本系统用户」）——见 {@link UserService#listForAdminScoped} 契约。
     *
     * <p>实现要点：
     * <ul>
     *   <li>判据用 <b>EXISTS 子查询</b>而非 JOIN：一个用户在本应用可能有多条绑定，
     *       JOIN 会让同一用户占多行 → 分页总数虚高、列表出现重复行。</li>
     *   <li>先查 id 页（带 LIMIT/OFFSET），再用实体 Mapper 回查，
     *       保证 {@code @TableLogic} 与字段映射与平台查询完全一致（不手写 row→entity）。</li>
     *   <li>一次性回填整页的 {@code appRoles}，避免 N+1。</li>
     * </ul>
     */
    @Override
    public PageResult<User> listForAdminScoped(String clientId, String realmId, String keyword,
                                               int page, int size) {
        StringBuilder sql = new StringBuilder("""
                FROM user u
                WHERE u.deleted = 0
                  AND (
                        EXISTS (SELECT 1 FROM sys_user_role ur
                                WHERE ur.user_id = u.id AND ur.client_id = ?)
                     OR EXISTS (SELECT 1 FROM app_account_mapping m
                                WHERE m.user_id = u.id AND m.client_id = ? AND m.status = 1)
                     OR u.role IN ('admin', 'superadmin')
                  )
                """);
        List<Object> args = new ArrayList<>();
        args.add(clientId);
        args.add(clientId);
        if (realmId != null && !realmId.isBlank()) {
            sql.append(" AND u.realm_id = ?");
            args.add(realmId);
        }
        if (keyword != null && !keyword.isBlank()) {
            sql.append(" AND (u.username LIKE ? OR u.email LIKE ? OR u.nickname LIKE ?)");
            String like = "%" + keyword + "%";
            args.add(like);
            args.add(like);
            args.add(like);
        }

        Long total = jdbcTemplate.queryForObject("SELECT COUNT(*) " + sql, Long.class, args.toArray());
        long totalVal = total == null ? 0L : total;

        List<Object> pageArgs = new ArrayList<>(args);
        pageArgs.add(size);
        pageArgs.add((page - 1) * size);
        List<Long> ids = jdbcTemplate.queryForList(
                "SELECT u.id " + sql + " ORDER BY u.created_at DESC LIMIT ? OFFSET ?",
                Long.class, pageArgs.toArray());
        if (ids.isEmpty()) {
            return PageResult.of(List.of(), totalVal, page, size);
        }

        Map<Long, User> byId = userMapper.selectBatchIds(ids).stream()
                .collect(Collectors.toMap(User::getId, u -> u));
        List<User> ordered = ids.stream().map(byId::get).filter(Objects::nonNull).collect(Collectors.toList());
        ordered.forEach(u -> u.setPassword(null));
        fillAppRoles(clientId, ordered);
        return PageResult.of(ordered, totalVal, page, size);
    }

    /** 回填「该用户在本应用（client）下的角色」→ {@code [{id,code,name}]}（整页一次查询，避免 N+1） */
    private void fillAppRoles(String clientId, List<User> users) {
        if (users.isEmpty()) {
            return;
        }
        // idList 由实体主键拼装，不含外部输入，无注入风险
        String idList = users.stream().map(u -> String.valueOf(u.getId())).collect(Collectors.joining(","));
        List<Map<String, Object>> bindings = jdbcTemplate.queryForList(
                "SELECT ur.user_id AS userId, r.id AS id, r.code AS code, r.name AS name "
                        + "FROM sys_user_role ur JOIN sys_role r ON r.id = ur.role_id "
                        + "WHERE ur.client_id = ? AND ur.user_id IN (" + idList + ")",
                clientId);
        Map<Long, List<Map<String, Object>>> byUser = new HashMap<>();
        for (Map<String, Object> b : bindings) {
            Long uid = ((Number) b.get("userId")).longValue();
            Map<String, Object> role = new LinkedHashMap<>();
            role.put("id", b.get("id"));
            role.put("code", b.get("code"));
            role.put("name", b.get("name"));
            byUser.computeIfAbsent(uid, k -> new ArrayList<>()).add(role);
        }
        users.forEach(u -> u.setAppRoles(byUser.getOrDefault(u.getId(), List.of())));
    }

    @Override
    @Transactional
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
        // uk_username 唯一索引不区分 deleted，软删行仍占用用户名；
        // 不预检会出现"删除后重建同名用户"撞唯一键 500（2026-09-12 实测）
        if (userMapper.countByUsernameIncludingDeleted(username) > 0) {
            throw new BusinessException("用户名已被历史账号占用（同名账号曾被删除），请更换用户名");
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(normalizedRole);
        user.setRealmId(normalizedRealm);
        user.setNickname(nickname);
        user.setEmail(email);
        user.setStatus(1);
        try {
            userMapper.insert(user);
        } catch (org.springframework.dao.DuplicateKeyException e) {
            // 并发窗口兜底：预检通过后另一请求恰好先插入同名
            throw new BusinessException("用户名已存在");
        }
        user.setPassword(null);

        operationLogService.log(operatorId, operatorName(operatorId), "user.create",
                "user", user.getId(), "创建用户 " + username + ", role=" + normalizedRole, null);
        return user;
    }

    @Override
    @Transactional
    public User updateUser(Long userId, String role, Integer status, String nickname,
                           String email, Long operatorId) {
        User user = userMapper.selectById(userId);
        if (user == null) {
            throw new BusinessException("用户不存在");
        }
        boolean targetSuper = ROLE_SUPERADMIN.equals(user.getRole());
        String opName = operatorName(operatorId);

        // 自身保护（防误操作锁死在管理界面外）
        if (userId.equals(operatorId)) {
            if (role != null && !"admin".equals(normalizeRole(role)) && !ROLE_SUPERADMIN.equals(normalizeRole(role))) {
                throw new BusinessException("不能修改自己的角色");
            }
            if (status != null && status == 0) {
                throw new BusinessException("不能禁用自己");
            }
        }
        // superadmin 不可被降级 / 禁用（任何操作者，含自己）
        if (targetSuper) {
            if (role != null && !ROLE_SUPERADMIN.equals(normalizeRole(role))) {
                throw new BusinessException("超级管理员不可被降级");
            }
            if (status != null && status == 0) {
                throw new BusinessException("超级管理员不可被禁用");
            }
        }

        boolean disabling = status != null && status == 0 && user.getStatus() != 0;
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

        // 禁用即踢下线：版本 +1 使已签发 token 立即失效，并回收 refresh token
        if (disabling) {
            revokeUserTokens(userId);
        }

        operationLogService.log(operatorId, opName, "user.update", "user", userId,
                "更新用户 status=" + user.getStatus() + ", role=" + user.getRole(), null);
        user.setPassword(null);
        return user;
    }

    @Override
    @Transactional
    public void deleteUser(Long userId, Long operatorId) {
        if (userId.equals(operatorId)) {
            throw new BusinessException("不能删除自己");
        }
        User user = userMapper.selectById(userId);
        if (user == null) {
            throw new BusinessException("用户不存在");
        }
        String opName = operatorName(operatorId);

        // superadmin 不可删除（任何操作者）。配合「不可降级 / 不可禁用」，superadmin 集合恒定，
        // 因此无需再单独统计保底数量
        if (ROLE_SUPERADMIN.equals(user.getRole())) {
            throw new BusinessException("超级管理员不可删除");
        }
        // 保底：至少保留 1 个 status=1 的管理员（admin ∪ superadmin——否则删光 admin
        // 只剩 superadmin 时会误拦正常删除）
        if ("admin".equals(user.getRole()) || ROLE_SUPERADMIN.equals(user.getRole())) {
            Long adminCount = userMapper.selectCount(new LambdaQueryWrapper<User>()
                    .in(User::getRole, "admin", ROLE_SUPERADMIN).eq(User::getStatus, 1));
            if (adminCount != null && adminCount <= 1) {
                throw new BusinessException("系统至少保留一个管理员，禁止删除");
            }
        }

        userMapper.deleteById(userId); // @TableLogic 软删除
        revokeUserTokens(userId);      // 删除即踢下线
        operationLogService.log(operatorId, opName, "user.delete", "user", userId,
                "删除用户 " + user.getUsername(), null);
    }

    @Override
    @Transactional
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

        revokeUserTokens(userId); // 改密即踢下线
        operationLogService.log(operatorId, operatorName(operatorId), "user.reset_password",
                "user", userId, "管理员重置密码 " + user.getUsername(), null);
    }

    private String normalizeRole(String role) {
        if (role == null || role.isBlank()) {
            return "user";
        }
        String r = role.trim().toLowerCase();
        if (!"admin".equals(r) && !"user".equals(r) && !ROLE_SUPERADMIN.equals(r)) {
            throw new BusinessException("角色只允许 admin/user/" + ROLE_SUPERADMIN);
        }
        return r;
    }

    /** 使该用户已签发 token 失效并回收 refresh token（禁用/删除/改密共用） */
    private void revokeUserTokens(Long userId) {
        tokenVersionService.bump(userId);
        refreshTokenMapper.delete(new LambdaQueryWrapper<RefreshToken>().eq(RefreshToken::getUserId, userId));
    }

    private String operatorName(Long operatorId) {
        if (operatorId == null) {
            return null;
        }
        User op = userMapper.selectById(operatorId);
        return op == null ? null : op.getUsername();
    }
}
