package com.marschat.authcenter.config;

import com.marschat.authcenter.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
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
                new LoginUrlAuthenticationEntryPoint("/login.html"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
        return http.build();
    }

    /** OIDC 端点 CORS 白名单：kb-web SPA 三环境 origin（公网 / LAN / 本地开发） */
    @org.springframework.context.annotation.Bean
    public org.springframework.web.cors.CorsConfigurationSource oidcCorsConfigurationSource() {
        org.springframework.web.cors.CorsConfiguration config = new org.springframework.web.cors.CorsConfiguration();
        config.setAllowedOrigins(java.util.List.of(
                // auth-center 自身原点（同源 POST 到 /oauth2/token 等端点时不应被拦）
                "https://auth.marschat.online",
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
     * 链2：SSO 登录表单页（品牌化自定义页），供浏览器授权跳转登录用。
     * 用户名密码走 user 表（UserDetailsServiceImpl 同时支持用户名/userId 查找）。
     *
     * 2026-09-11（L032）：原先用 SAS/Spring 默认英文页（formLogin(withDefaults) 未指定 loginPage，
     * 浏览器看到 <title>Please sign in</title> 的裸表单）。改为静态 login.html（品牌 + 忘记密码入口），
     * 登录提交仍走 Spring Security 的 POST /login（UsernamePasswordAuthenticationFilter），不进 MVC。
     * 同批放行 /forgot-password.html —— 该页同时是 myfrp 登录页「忘记密码」历史死链指向的地址（L029）。
     *
     * 2026-09-11（Phase 6 紧密型接入）：新增放行 /auth/session（会话探针）与 /auth/slo（统一登出）。
     * 这两个端点**必须挂在有会话的链上**——链3 是 STATELESS，SecurityContextHolder 恒空，
     * 探针会永远返回未登录。同时本链开启 CORS（凭据模式），供各应用跨域 XHR 探针使用。
     */
    @Bean
    public SecurityFilterChain loginPageSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/login", "/login.html", "/forgot-password.html", "/error",
                    "/auth/session", "/auth/slo")
            .cors(cors -> cors.configurationSource(ssoAuxCorsConfigurationSource()))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .formLogin(form -> form
                    .loginPage("/login.html")
                    .loginProcessingUrl("/login")
                    .permitAll())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    /**
     * 会话探针 / 统一登出的 CORS 配置（Phase 6）。
     * <p>与 OIDC 端点那份的关键差别：<b>必须允许携带凭据</b>（浏览器要带上 auth-center 的 JSESSIONID，
     * HttpOnly 只能由浏览器自动附带）。因此 {@code Allow-Origin} 必须回显具体原点，
     * 不能用通配符 {@code *}（规范禁止二者共存）。
     * <p>仅覆盖 *.marschat.online 各应用域 + 内网/LAN 直连入口 + 本地开发端口。
     */
    @Bean
    public org.springframework.web.cors.CorsConfigurationSource ssoAuxCorsConfigurationSource() {
        org.springframework.web.cors.CorsConfiguration config = new org.springframework.web.cors.CorsConfiguration();
        config.setAllowedOrigins(java.util.List.of(
                // auth-center 自身原点（同源请求不应被 CORS 拦截；表单 POST 会带 Origin 头）
                "https://auth.marschat.online",
                "http://192.168.31.105:8085",
                "http://localhost:8085",
                // cosmic-studio 方案A 接入（cosmic.marschat.online 前端跨源探针 /auth/session）
                "https://cosmic.marschat.online",
                "https://main.marschat.online",
                "https://kb.marschat.online",
                "https://monitor.marschat.online",
                "https://tools.marschat.online",
                "https://frp.marschat.online",
                "https://memory.marschat.online",
                "https://tokenhub.marschat.online",
                "http://192.168.31.105",
                "http://192.168.31.105:8310",
                "http://192.168.31.105:18080",
                "http://192.168.31.182:18080",
                "http://localhost:5173",
                "http://localhost:3001",
                "http://localhost:3002",
                "http://localhost:8310"));
        config.setAllowedMethods(java.util.List.of("GET", "POST", "OPTIONS"));
        config.setAllowedHeaders(java.util.List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        org.springframework.web.cors.UrlBasedCorsConfigurationSource source =
                new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
        // ⚠️ 只对真正需要跨域 XHR 的两个 SSO 辅助端点生效，不要用 "/**"。
        // 本链同时还承载 /login（浏览器表单 POST 必带 Origin 头）：
        // 若把 CORS 全局启用，同源表单 POST 会因原点不在白名单被 CorsFilter 判为非法 → 403
        // "Invalid CORS request"，登录被彻底打死（2026-09-11 实测回归）。
        source.registerCorsConfiguration("/auth/session", config);
        source.registerCorsConfiguration("/auth/slo", config);
        return source;
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

    /**
     * 链4：邮箱验证码登录（独立端点，不接入现有 /auth/login 主链路，避免回归）。
     * 发码 / 验码登录均匿名可访问；order 高于链3("/**")以确保优先匹配。
     */
    @Bean
    @Order(1)
    public SecurityFilterChain mailCodeLoginSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/auth/mail-login/**")
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
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
