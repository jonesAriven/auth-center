package com.marschat.authcenter.config;

import com.marschat.common.trace.TraceIdInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web MVC 配置
 * <p>
 * 显式注册 TraceIdInterceptor，确保 MDC traceId 在每次请求时被填充。
 * 不依赖 kb-common 的 AutoConfiguration 机制，避免 Spring Boot 3.x 兼容性问题。
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new TraceIdInterceptor())
                .addPathPatterns("/**");
    }
}
