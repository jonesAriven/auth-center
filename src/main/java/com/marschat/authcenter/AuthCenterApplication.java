package com.marschat.authcenter;

import com.marschat.common.event.EventAutoConfig;
import com.marschat.common.exception.GlobalExceptionHandler;
import com.marschat.common.trace.TraceIdAutoConfig;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * auth-center 认证微服务启动类
 * <p>
 * 通过 @Import 引入 kb-common 的全局异常处理器、TraceId 链路追踪和事件总线。
 * @EnableAsync 启用异步支持，用于操作日志异步写入
 */
@SpringBootApplication
@MapperScan("com.marschat.authcenter.mapper")
@Import({GlobalExceptionHandler.class, TraceIdAutoConfig.class, EventAutoConfig.class})
@EnableAsync
@EnableDiscoveryClient
public class AuthCenterApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthCenterApplication.class, args);
    }
}
