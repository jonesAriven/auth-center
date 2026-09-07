package com.marschat.authcenter.security;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.marschat.authcenter.entity.JwtBlacklist;
import com.marschat.authcenter.mapper.JwtBlacklistMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;
    private final JwtBlacklistMapper jwtBlacklistMapper;
    private final org.springframework.security.oauth2.jwt.JwtDecoder jwtDecoder;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = resolveToken(request);

        if (StringUtils.hasText(token)) {
            if (isBlacklisted(token)) {
                sendUnauthorized(response, "Token已失效");
                return;
            }

            try {
                // 验签路径区分 legacy / OIDC：HS256 本地验签通过即 legacy（auth-center 自签 token），
                // 否则视为 auth-center 签发的 RS256 OIDC token（与 gateway JwtAuthFilter 口径一致）。
                boolean legacy = jwtTokenProvider.validateToken(token);

                String principal;
                if (legacy) {
                    // legacy HS256 token：仅访问令牌允许通过（OIDC token 无 type claim，不在此校验）
                    String tokenType = jwtTokenProvider.getTokenType(token);
                    if (!"access".equals(tokenType)) {
                        sendUnauthorized(response, "令牌类型错误，请使用访问令牌");
                        return;
                    }
                    principal = String.valueOf(jwtTokenProvider.getUserIdFromToken(token));
                } else {
                    // OIDC RS256 token（auth-center 签发，claims: uid/username/role）
                    try {
                        var jwt = jwtDecoder.decode(token);
                        String uid = jwt.getClaimAsString("uid");
                        if (uid == null || uid.isBlank()) {
                            uid = jwt.getSubject();
                        }
                        principal = uid;
                    } catch (Exception rsError) {
                        log.debug("RS256 验签失败: {}", rsError.getMessage());
                        sendUnauthorized(response, "Token无效或已过期");
                        return;
                    }
                }

                UserDetails userDetails = userDetailsService.loadUserByUsername(principal);
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                log.warn("JWT认证失败: {}", e.getMessage());
                sendUnauthorized(response, "Token无效或已过期");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private boolean isBlacklisted(String token) {
        return jwtBlacklistMapper.selectCount(
                new LambdaQueryWrapper<JwtBlacklist>()
                        .eq(JwtBlacklist::getToken, token)
                        .gt(JwtBlacklist::getExpireAt, LocalDateTime.now())
        ) > 0;
    }

    private void sendUnauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("{\"code\":401,\"message\":\"" + message + "\",\"data\":null}");
    }
}
