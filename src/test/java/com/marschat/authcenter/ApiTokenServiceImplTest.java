package com.marschat.authcenter;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.marschat.authcenter.dto.ApiTokenRequest;
import com.marschat.authcenter.dto.ApiTokenResponse;
import com.marschat.authcenter.entity.ApiToken;
import com.marschat.authcenter.mapper.ApiTokenMapper;
import com.marschat.authcenter.service.impl.ApiTokenServiceImpl;
import com.marschat.authcenter.util.CryptoUtil;
import com.marschat.common.exception.BusinessException;
import com.marschat.common.exception.NotFoundException;
import com.marschat.common.page.PageResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("API Token 服务单元测试")
class ApiTokenServiceImplTest {

    @Mock private ApiTokenMapper apiTokenMapper;
    @Mock private CryptoUtil cryptoUtil;

    @InjectMocks
    private ApiTokenServiceImpl apiTokenService;

    private ApiToken testToken;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(apiTokenService, "tokenPrefix", "kb_");
        ReflectionTestUtils.setField(apiTokenService, "defaultExpireDays", 30);

        testToken = new ApiToken();
        testToken.setId(1L);
        testToken.setUserId(100L);
        testToken.setName("运维Token");
        testToken.setTokenEncrypted("encrypted-value");
        testToken.setTokenPrefix("kb_abc12345****");
        testToken.setScope("ops:read");
        testToken.setStatus(0);
        testToken.setExpireAt(LocalDateTime.now().plusDays(10));
    }

    @Test
    @DisplayName("创建 Token - 带过期时间和权限范围")
    void create_withExpireAtAndScope() {
        ApiTokenRequest request = new ApiTokenRequest();
        request.setName("新Token");
        request.setScope("ops:read,ops:write");
        request.setExpireAt(LocalDateTime.now().plusDays(7));

        when(cryptoUtil.encrypt(anyString())).thenReturn("encrypted");
        when(apiTokenMapper.insert(any(ApiToken.class))).thenAnswer(invocation -> {
            ApiToken t = invocation.getArgument(0);
            t.setId(10L);
            return 1;
        });

        ApiTokenResponse response = apiTokenService.create(100L, request);

        assertNotNull(response);
        assertEquals(10L, response.getId());
        assertEquals("新Token", response.getName());
        assertNotNull(response.getToken());
        assertTrue(response.getToken().startsWith("kb_"));
        assertNotNull(response.getTokenPrefix());
        assertEquals("ops:read,ops:write", response.getScope());
        assertNotNull(response.getExpireAt());
    }

    @Test
    @DisplayName("创建 Token - 无过期时间使用默认天数，无 scope 设为空串")
    void create_withoutExpireAtAndScope() {
        ApiTokenRequest request = new ApiTokenRequest();
        request.setName("默认Token");
        request.setScope(null);
        request.setExpireAt(null);

        when(cryptoUtil.encrypt(anyString())).thenReturn("encrypted");
        when(apiTokenMapper.insert(any(ApiToken.class))).thenAnswer(invocation -> {
            ApiToken t = invocation.getArgument(0);
            t.setId(11L);
            return 1;
        });

        ApiTokenResponse response = apiTokenService.create(100L, request);

        assertNotNull(response);
        assertEquals("", response.getScope());
        assertNotNull(response.getExpireAt());
    }

    @Test
    @DisplayName("列表查询 - 返回分页结果并清除加密值")
    void list_returnsPageResult_andClearsEncrypted() {
        ApiToken t1 = new ApiToken();
        t1.setId(1L);
        t1.setTokenEncrypted("secret1");
        ApiToken t2 = new ApiToken();
        t2.setId(2L);
        t2.setTokenEncrypted("secret2");

        Page<ApiToken> page = new Page<>(1, 20);
        page.setRecords(Arrays.asList(t1, t2));
        page.setTotal(2);

        when(apiTokenMapper.selectPage(any(Page.class), any())).thenReturn(page);

        PageResult<ApiToken> result = apiTokenService.list(100L, 1, 20);

        assertNotNull(result);
        assertEquals(2, result.getTotal());
        assertEquals(2, result.getList().size());
        assertNull(result.getList().get(0).getTokenEncrypted());
        assertNull(result.getList().get(1).getTokenEncrypted());
    }

    @Test
    @DisplayName("删除 Token - 成功删除")
    void delete_success() {
        when(apiTokenMapper.selectById(1L)).thenReturn(testToken);

        assertDoesNotThrow(() -> apiTokenService.delete(100L, 1L));
        verify(apiTokenMapper).deleteById(1L);
    }

    @Test
    @DisplayName("删除 Token - Token 不存在")
    void delete_tokenNotFound() {
        when(apiTokenMapper.selectById(999L)).thenReturn(null);
        assertThrows(NotFoundException.class, () -> apiTokenService.delete(100L, 999L));
    }

    @Test
    @DisplayName("删除 Token - 无权操作")
    void delete_noOwnership() {
        when(apiTokenMapper.selectById(1L)).thenReturn(testToken);
        BusinessException ex = assertThrows(BusinessException.class, () -> apiTokenService.delete(200L, 1L));
        assertEquals(403, ex.getCode());
    }

    @Test
    @DisplayName("切换状态 - 启用转禁用")
    void toggleStatus_enabledToDisabled() {
        testToken.setStatus(0);
        when(apiTokenMapper.selectById(1L)).thenReturn(testToken);

        assertDoesNotThrow(() -> apiTokenService.toggleStatus(100L, 1L));
        verify(apiTokenMapper).updateById(any(ApiToken.class));
        assertEquals(1, testToken.getStatus());
    }

    @Test
    @DisplayName("切换状态 - 禁用转启用")
    void toggleStatus_disabledToEnabled() {
        testToken.setStatus(1);
        when(apiTokenMapper.selectById(1L)).thenReturn(testToken);

        assertDoesNotThrow(() -> apiTokenService.toggleStatus(100L, 1L));
        verify(apiTokenMapper).updateById(any(ApiToken.class));
        assertEquals(0, testToken.getStatus());
    }

    @Test
    @DisplayName("切换状态 - Token 不存在")
    void toggleStatus_tokenNotFound() {
        when(apiTokenMapper.selectById(999L)).thenReturn(null);
        assertThrows(NotFoundException.class, () -> apiTokenService.toggleStatus(100L, 999L));
    }

    @Test
    @DisplayName("切换状态 - 无权操作")
    void toggleStatus_noOwnership() {
        when(apiTokenMapper.selectById(1L)).thenReturn(testToken);
        assertThrows(BusinessException.class, () -> apiTokenService.toggleStatus(200L, 1L));
    }

    @Test
    @DisplayName("验证 Token - 空Token抛异常")
    void verify_nullToken() {
        BusinessException ex = assertThrows(BusinessException.class, () -> apiTokenService.verify(null));
        assertEquals(401, ex.getCode());
    }

    @Test
    @DisplayName("验证 Token - 空白Token抛异常")
    void verify_blankToken() {
        BusinessException ex = assertThrows(BusinessException.class, () -> apiTokenService.verify("   "));
        assertEquals(401, ex.getCode());
    }

    @Test
    @DisplayName("验证 Token - 匹配成功且未过期，更新最后使用时间")
    void verify_success() {
        testToken.setExpireAt(LocalDateTime.now().plusDays(5));
        when(apiTokenMapper.selectList(any())).thenReturn(Arrays.asList(testToken));
        when(cryptoUtil.decrypt("encrypted-value")).thenReturn("kb_match_token");

        ApiToken result = apiTokenService.verify("kb_match_token");

        assertNotNull(result);
        assertNotNull(result.getLastUsedAt());
        verify(apiTokenMapper).updateById(any(ApiToken.class));
    }

    @Test
    @DisplayName("验证 Token - 匹配成功但已过期")
    void verify_expiredToken() {
        testToken.setExpireAt(LocalDateTime.now().minusDays(1));
        when(apiTokenMapper.selectList(any())).thenReturn(Arrays.asList(testToken));
        when(cryptoUtil.decrypt("encrypted-value")).thenReturn("kb_match_token");

        BusinessException ex = assertThrows(BusinessException.class, () -> apiTokenService.verify("kb_match_token"));
        assertEquals(401, ex.getCode());
    }

    @Test
    @DisplayName("验证 Token - 匹配成功且 expireAt 为 null（永不过期）")
    void verify_nullExpireAt_neverExpires() {
        testToken.setExpireAt(null);
        when(apiTokenMapper.selectList(any())).thenReturn(Arrays.asList(testToken));
        when(cryptoUtil.decrypt("encrypted-value")).thenReturn("kb_match_token");

        ApiToken result = apiTokenService.verify("kb_match_token");
        assertNotNull(result);
    }

    @Test
    @DisplayName("验证 Token - 无匹配项抛异常")
    void verify_noMatch() {
        when(apiTokenMapper.selectList(any())).thenReturn(Arrays.asList(testToken));
        when(cryptoUtil.decrypt("encrypted-value")).thenReturn("other_token");

        BusinessException ex = assertThrows(BusinessException.class, () -> apiTokenService.verify("kb_match_token"));
        assertEquals(401, ex.getCode());
    }

    @Test
    @DisplayName("验证 Token - 候选为空列表抛异常")
    void verify_emptyCandidates() {
        when(apiTokenMapper.selectList(any())).thenReturn(Collections.emptyList());

        BusinessException ex = assertThrows(BusinessException.class, () -> apiTokenService.verify("kb_match_token"));
        assertEquals(401, ex.getCode());
    }

    @Test
    @DisplayName("验证 Token - 短Token使用全串作为前缀过滤")
    void verify_shortToken_usesFullTokenAsPrefix() {
        String shortToken = "kb_short";
        testToken.setExpireAt(LocalDateTime.now().plusDays(5));
        when(apiTokenMapper.selectList(any())).thenReturn(Arrays.asList(testToken));
        when(cryptoUtil.decrypt("encrypted-value")).thenReturn(shortToken);

        ApiToken result = apiTokenService.verify(shortToken);
        assertNotNull(result);
    }

    @Test
    @DisplayName("查询用户活跃 Token 列表")
    void listByUser_returnsActiveTokens() {
        when(apiTokenMapper.selectList(any())).thenReturn(Arrays.asList(testToken));

        List<ApiToken> result = apiTokenService.listByUser(100L);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("运维Token", result.get(0).getName());
    }
}
