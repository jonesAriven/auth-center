package com.marschat.authcenter.security;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserMapper userMapper;

    /**
     * 双模式查找：
     * - 数字 principal = userId（legacy JWT 过滤器用）
     * - 字符串 principal = username（OIDC 表单登录用）
     * 角色取 user.role，ROLE_ADMIN 才能进管理接口。
     */
    @Override
    public UserDetails loadUserByUsername(String principal) throws UsernameNotFoundException {
        User user = resolveUser(principal);
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在: " + principal);
        }
        if (user.getStatus() == 0) {
            throw new UsernameNotFoundException("用户已被禁用: " + principal);
        }
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        // superadmin ⊇ admin：管理接口 @PreAuthorize("hasRole('ADMIN')") 对超管同样放行
        // （层级包含）；否则 role=superadmin 的用户反而进不了 /admin/**（2026-09-13 实测）
        if ("admin".equals(user.getRole()) || "superadmin".equals(user.getRole())) {
            authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }
        if ("superadmin".equals(user.getRole())) {
            authorities.add(new SimpleGrantedAuthority("ROLE_SUPERADMIN"));
        }
        return new org.springframework.security.core.userdetails.User(
                String.valueOf(user.getId()),
                user.getPassword(),
                authorities
        );
    }

    private User resolveUser(String principal) {
        try {
            return userMapper.selectById(Long.parseLong(principal));
        } catch (NumberFormatException e) {
            return userMapper.selectOne(new LambdaQueryWrapper<User>().eq(User::getUsername, principal));
        }
    }
}
