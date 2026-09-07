package com.marschat.authcenter.config;

import com.marschat.authcenter.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final org.springframework.security.oauth2.jwt.JwtDecoder jwtDecoder;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          org.springframework.security.oauth2.jwt.JwtDecoder jwtDecoder) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.jwtDecoder = jwtDecoder;
    }

    /**
     * 链1：OIDC 授权服务器端点（/oauth2/authorize、/oauth2/token、/oauth2/jwks、/userinfo…）
     * 浏览器跳转需要会话，未登录跳 /login 表单页。
     * 2026-09-07 kb-web SPA 接入：public client + PKCE，浏览器直连 /oauth2/token，需放行 CORS。
     */
    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        authorizationServerConfigurer.oidc(org.springframework.security.config.Customizer.withDefaults());
        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .authorizeHttpRequests(auth -> auth
                // 发现/公钥端点必须匿名可读，否则客户端拿不到 JWKS
                .requestMatchers("/oauth2/jwks", "/.well-known/openid-configuration",
                        "/.well-known/oauth-authorization-server").permitAll()
                // CORS 预检放行（kb-web SPA 跨域换 token）
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .anyRequest().authenticated())
            // userinfo 端点需要资源服务器能力验 RS256 Bearer token
            .oauth2ResourceServer(rs -> rs.jwt(jwt -> jwt.decoder(jwtDecoder)))
            .cors(cors -> cors.configurationSource(oidcCorsConfigurationSource()))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .csrf(AbstractHttpConfigurer::disable)
            .apply(authorizationServerConfigurer);
        http.exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
        return http.build();
    }

    /** OIDC 端点 CORS 白名单：kb-web SPA 三环境 origin（公网 / LAN / 本地开发） */
    @org.springframework.context.annotation.Bean
    public org.springframework.web.cors.CorsConfigurationSource oidcCorsConfigurationSource() {
        org.springframework.web.cors.CorsConfiguration config = new org.springframework.web.cors.CorsConfiguration();
        config.setAllowedOrigins(java.util.List.of(
                "https://kb.marschat.online",
                "http://192.168.31.105",
                "http://localhost:5173",
                "https://monitor.marschat.online",
                "http://localhost:3002",
                // P2 批量接入（2026-09-07）：activecode / memory / tokenhub
                "https://tools.marschat.online",
                "http://192.168.31.182:18080",
                "https://memory.marschat.online",
                "http://192.168.31.105:8720",
                "https://tokenhub.marschat.online",
                "http://192.168.31.105:13000"));
        config.setAllowedMethods(java.util.List.of("GET", "POST", "OPTIONS"));
        config.setAllowedHeaders(java.util.List.of("*"));
        config.setAllowCredentials(false);
        config.setMaxAge(3600L);
        org.springframework.web.cors.UrlBasedCorsConfigurationSource source =
                new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * 链2：SSO 登录表单页（SAS 默认页），供浏览器授权跳转登录用。
     * 用户名密码走 user 表（UserDetailsServiceImpl 同时支持用户名/userId 查找）。
     */
    @Bean
    public SecurityFilterChain loginPageSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/login", "/error")
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .formLogin(org.springframework.security.config.Customizer.withDefaults())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    /** 链3：原有 API（legacy 直登接口 + 业务接口），保持无状态 JWT 验签，行为不变 */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/**")
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/login", "/auth/refresh").permitAll()
                .requestMatchers("/auth/forgot-password", "/auth/reset-password").permitAll()
                .requestMatchers("/auth/error-log/report").permitAll()
                .requestMatchers("/token/verify").permitAll()
                .requestMatchers("/actuator/**").permitAll()
                // M6: Swagger 文档端点公开
                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
