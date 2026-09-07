package com.marschat.authcenter;

import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.mapper.UserMapper;
import com.marschat.authcenter.service.impl.UserServiceImpl;
import com.marschat.common.exception.BusinessException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("用户服务单元测试")
class UserServiceImplTest {

    @Mock private UserMapper userMapper;
    @Mock private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserServiceImpl userService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("admin");
        testUser.setPassword("$2a$10$hashedPassword");
        testUser.setNickname("管理员");
        testUser.setStatus(1);
    }

    @Test
    @DisplayName("获取用户信息 - 正常返回且密码置空")
    void getProfileSuccess() {
        when(userMapper.selectById(1L)).thenReturn(testUser);

        User result = userService.getProfile(1L);

        assertNotNull(result);
        assertEquals("admin", result.getUsername());
        assertNull(result.getPassword());
    }

    @Test
    @DisplayName("获取用户信息 - 用户不存在")
    void getProfileNotFound() {
        when(userMapper.selectById(999L)).thenReturn(null);
        assertThrows(BusinessException.class, () -> userService.getProfile(999L));
    }

    @Test
    @DisplayName("修改密码 - 旧密码正确")
    void updatePasswordSuccess() {
        when(userMapper.selectById(1L)).thenReturn(testUser);
        when(passwordEncoder.matches("oldpass", "$2a$10$hashedPassword")).thenReturn(true);
        when(passwordEncoder.encode("newpass")).thenReturn("$2a$10$newHashed");

        assertDoesNotThrow(() -> userService.updatePassword(1L, "oldpass", "newpass"));
        verify(userMapper).updateById(any(User.class));
    }

    @Test
    @DisplayName("修改密码 - 旧密码错误")
    void updatePasswordWrongOld() {
        when(userMapper.selectById(1L)).thenReturn(testUser);
        when(passwordEncoder.matches("wrongold", "$2a$10$hashedPassword")).thenReturn(false);

        assertThrows(BusinessException.class, () -> userService.updatePassword(1L, "wrongold", "newpass"));
    }

    @Test
    @DisplayName("修改密码 - 用户不存在")
    void updatePasswordUserNotFound() {
        when(userMapper.selectById(999L)).thenReturn(null);
        assertThrows(BusinessException.class, () -> userService.updatePassword(999L, "old", "new"));
    }

    @Test
    @DisplayName("更新资料 - 昵称邮箱头像全部更新成功")
    void updateProfile_allFieldsSuccess() {
        testUser.setPhone("13800000000");
        when(userMapper.selectById(1L)).thenReturn(testUser);

        User result = userService.updateProfile(1L, "新昵称", "new@email.com", "13800000000", "avatar.png");

        assertNotNull(result);
        assertEquals("新昵称", result.getNickname());
        assertEquals("new@email.com", result.getEmail());
        assertEquals("avatar.png", result.getAvatar());
        assertNull(result.getPassword());
        verify(userMapper).updateById(any(User.class));
    }

    @Test
    @DisplayName("更新资料 - 手机号变更且与他人冲突")
    void updateProfile_phoneConflict() {
        testUser.setPhone("13800000000");
        when(userMapper.selectById(1L)).thenReturn(testUser);
        when(userMapper.selectOne(any())).thenReturn(new User());

        assertThrows(BusinessException.class,
                () -> userService.updateProfile(1L, null, null, "13900000000", null));
    }

    @Test
    @DisplayName("更新资料 - 手机号变更且无冲突，更新成功")
    void updateProfile_phoneChangeSuccess() {
        testUser.setPhone("13800000000");
        when(userMapper.selectById(1L)).thenReturn(testUser);
        when(userMapper.selectOne(any())).thenReturn(null);

        User result = userService.updateProfile(1L, null, null, "13900000000", null);

        assertNotNull(result);
        assertEquals("13900000000", result.getPhone());
        verify(userMapper).updateById(any(User.class));
    }

    @Test
    @DisplayName("更新资料 - 手机号未变更，不触发冲突检查")
    void updateProfile_phoneUnchanged() {
        testUser.setPhone("13800000000");
        when(userMapper.selectById(1L)).thenReturn(testUser);

        User result = userService.updateProfile(1L, "昵称", null, "13800000000", null);

        assertNotNull(result);
        assertEquals("13800000000", result.getPhone());
        verify(userMapper, never()).selectOne(any());
    }

    @Test
    @DisplayName("更新资料 - 手机号为 null，跳过手机号逻辑")
    void updateProfile_phoneNull() {
        when(userMapper.selectById(1L)).thenReturn(testUser);

        User result = userService.updateProfile(1L, "昵称", "email@test.com", null, "avatar.png");

        assertNotNull(result);
        assertEquals("昵称", result.getNickname());
        assertEquals("email@test.com", result.getEmail());
        verify(userMapper, never()).selectOne(any());
    }

    @Test
    @DisplayName("更新资料 - 用户不存在")
    void updateProfileUserNotFound() {
        when(userMapper.selectById(999L)).thenReturn(null);
        assertThrows(BusinessException.class,
                () -> userService.updateProfile(999L, "昵称", null, null, null));
    }
}
