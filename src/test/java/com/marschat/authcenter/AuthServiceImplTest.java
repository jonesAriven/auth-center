package com.marschat.authcenter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.marschat.authcenter.dto.LoginRequest;
import com.marschat.authcenter.dto.LoginResponse;
import com.marschat.authcenter.dto.RefreshRequest;
import com.marschat.authcenter.entity.RefreshToken;
import com.marschat.authcenter.entity.User;
import com.marschat.authcenter.mapper.JwtBlacklistMapper;
import com.marschat.authcenter.mapper.RefreshTokenMapper;
import com.marschat.authcenter.mapper.UserMapper;
import com.marschat.authcenter.security.JwtTokenProvider;
import com.marschat.authcenter.service.impl.AuthServiceImpl;
import com.marschat.common.exception.BusinessException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("认证服务单元测试")
class AuthServiceImplTest {

    @Mock private UserMapper userMapper;
    @Mock private RefreshTokenMapper refreshTokenMapper;
    @Mock private JwtBlacklistMapper jwtBlacklistMapper;
    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private RedisTemplate<String, Object> redisTemplate;
    @Mock private ValueOperations<String, Object> valueOperations;

    @InjectMocks
    private AuthServiceImpl authService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("admin");
        testUser.setPassword("$2a$10$hashedPassword");
        testUser.setStatus(1);
    }

    @Test
    @DisplayName("登录成功 - 返回 accessToken 和 refreshToken")
    void loginSuccess() {
        LoginRequest request = new LoginRequest();
        request.setUsername("admin");
        request.setPassword("admin123");

        when(userMapper.selectOne(any())).thenReturn(testUser);
        when(passwordEncoder.matches("admin123", "$2a$10$hashedPassword")).thenReturn(true);
        when(jwtTokenProvider.generateAccessToken(1L, "admin")).thenReturn("access-token");
        when(jwtTokenProvider.generateRefreshToken(1L)).thenReturn("refresh-token");
        when(jwtTokenProvider.getAccessTokenExpiration()).thenReturn(900000L);

        LoginResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("access-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());
        verify(refreshTokenMapper).insert(any());
    }

    @Test
    @DisplayName("登录失败 - 用户不存在")
    void loginUserNotFound() {
        LoginRequest request = new LoginRequest();
        request.setUsername("nonexistent");
        request.setPassword("password");

        when(userMapper.selectOne(any())).thenReturn(null);

        assertThrows(BusinessException.class, () -> authService.login(request));
    }

    @Test
    @DisplayName("登录失败 - 密码错误")
    void loginWrongPassword() {
        LoginRequest request = new LoginRequest();
        request.setUsername("admin");
        request.setPassword("wrongpass");

        when(userMapper.selectOne(any())).thenReturn(testUser);
        when(passwordEncoder.matches("wrongpass", "$2a$10$hashedPassword")).thenReturn(false);

        assertThrows(BusinessException.class, () -> authService.login(request));
    }

    @Test
    @DisplayName("登录失败 - 用户已被禁用")
    void loginUserDisabled() {
        testUser.setStatus(0);
        LoginRequest request = new LoginRequest();
        request.setUsername("admin");
        request.setPassword("admin123");

        when(userMapper.selectOne(any())).thenReturn(testUser);

        assertThrows(BusinessException.class, () -> authService.login(request));
    }

    @Test
    @DisplayName("登出 - accessToken 为空，直接返回")
    void logoutNullToken() {
        assertDoesNotThrow(() -> authService.logout(null));
        verify(jwtBlacklistMapper, never()).insert(any());
    }

    @Test
    @DisplayName("登出 - 无效 token，不写入黑名单")
    void logoutInvalidToken() {
        when(jwtTokenProvider.validateToken("invalid")).thenReturn(false);

        assertDoesNotThrow(() -> authService.logout("invalid"));
        verify(jwtBlacklistMapper, never()).insert(any());
    }

    @Test
    @DisplayName("登出 - 有效 token，写入黑名单并发布事件")
    void logoutValidToken() {
        when(jwtTokenProvider.validateToken("access-token")).thenReturn(true);
        when(jwtTokenProvider.getExpirationFromToken("access-token")).thenReturn(new Date());
        when(jwtTokenProvider.getUserIdFromToken("access-token")).thenReturn(1L);

        assertDoesNotThrow(() -> authService.logout("access-token"));
        verify(jwtBlacklistMapper).insert(any());
    }

    @Test
    @DisplayName("刷新令牌 - RefreshToken 无效或已过期")
    void refreshInvalidToken() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("invalid-token");
        when(jwtTokenProvider.validateToken("invalid-token")).thenReturn(false);

        BusinessException ex = assertThrows(BusinessException.class, () -> authService.refresh(request));
        assertEquals(401, ex.getCode());
    }

    @Test
    @DisplayName("刷新令牌 - Token 类型不是 refresh")
    void refreshWrongTokenType() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("access-token");
        when(jwtTokenProvider.validateToken("access-token")).thenReturn(true);
        when(jwtTokenProvider.getTokenType("access-token")).thenReturn("access");

        BusinessException ex = assertThrows(BusinessException.class, () -> authService.refresh(request));
        assertEquals(401, ex.getCode());
    }

    @Test
    @DisplayName("刷新令牌 - RefreshToken 不存在于数据库")
    void refreshTokenNotFound() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("refresh-token");
        when(jwtTokenProvider.validateToken("refresh-token")).thenReturn(true);
        when(jwtTokenProvider.getTokenType("refresh-token")).thenReturn("refresh");
        when(jwtTokenProvider.getUserIdFromToken("refresh-token")).thenReturn(1L);
        when(refreshTokenMapper.selectList(any())).thenReturn(Collections.emptyList());

        BusinessException ex = assertThrows(BusinessException.class, () -> authService.refresh(request));
        assertEquals(401, ex.getCode());
    }

    @Test
    @DisplayName("刷新令牌 - 用户不存在")
    void refreshUserNotFound() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("refresh-token");
        RefreshToken stored = new RefreshToken();
        stored.setUserId(1L);
        stored.setToken("refresh-token");
        when(jwtTokenProvider.validateToken("refresh-token")).thenReturn(true);
        when(jwtTokenProvider.getTokenType("refresh-token")).thenReturn("refresh");
        when(jwtTokenProvider.getUserIdFromToken("refresh-token")).thenReturn(1L);
        when(refreshTokenMapper.selectList(any())).thenReturn(Arrays.asList(stored));
        when(userMapper.selectById(1L)).thenReturn(null);

        BusinessException ex = assertThrows(BusinessException.class, () -> authService.refresh(request));
        assertEquals(401, ex.getCode());
    }

    @Test
    @DisplayName("刷新令牌 - 用户已被禁用")
    void refreshUserDisabled() {
        testUser.setStatus(0);
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("refresh-token");
        RefreshToken stored = new RefreshToken();
        stored.setUserId(1L);
        stored.setToken("refresh-token");
        when(jwtTokenProvider.validateToken("refresh-token")).thenReturn(true);
        when(jwtTokenProvider.getTokenType("refresh-token")).thenReturn("refresh");
        when(jwtTokenProvider.getUserIdFromToken("refresh-token")).thenReturn(1L);
        when(refreshTokenMapper.selectList(any())).thenReturn(Arrays.asList(stored));
        when(userMapper.selectById(1L)).thenReturn(testUser);

        BusinessException ex = assertThrows(BusinessException.class, () -> authService.refresh(request));
        assertEquals(401, ex.getCode());
    }

    @Test
    @DisplayName("刷新令牌 - 成功返回新的 accessToken 和 refreshToken")
    void refreshSuccess() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("refresh-token");
        RefreshToken stored = new RefreshToken();
        stored.setUserId(1L);
        stored.setToken("refresh-token");
        when(jwtTokenProvider.validateToken("refresh-token")).thenReturn(true);
        when(jwtTokenProvider.getTokenType("refresh-token")).thenReturn("refresh");
        when(jwtTokenProvider.getUserIdFromToken("refresh-token")).thenReturn(1L);
        when(refreshTokenMapper.selectList(any())).thenReturn(Arrays.asList(stored));
        when(userMapper.selectById(1L)).thenReturn(testUser);
        when(jwtTokenProvider.generateAccessToken(1L, "admin")).thenReturn("new-access");
        when(jwtTokenProvider.generateRefreshToken(1L)).thenReturn("new-refresh");
        when(jwtTokenProvider.getAccessTokenExpiration()).thenReturn(900000L);

        LoginResponse response = authService.refresh(request);

        assertNotNull(response);
        assertEquals("new-access", response.getAccessToken());
        assertEquals("new-refresh", response.getRefreshToken());
        assertEquals(900000L, response.getExpiresIn());
        assertNull(response.getUser().getPassword());
        verify(refreshTokenMapper).delete(any());
        verify(refreshTokenMapper).insert(any());
    }
}
