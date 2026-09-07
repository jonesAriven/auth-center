# auth-center 统一认证中心 Dockerfile（fka auth-center，2026-09-07 剥离改名）
FROM eclipse-temurin:21-jre-alpine

LABEL maintainer="marschat"

WORKDIR /app

# 复制构建产物（jar 名跟随 artifactId=auth-center）
COPY target/auth-center.jar /app/auth-center.jar

# 时区设置（直接复制时区文件，无需安装 tzdata 包）
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

EXPOSE 8081

ENV JAVA_OPTS="-Xms128m -Xmx256m -XX:+UseG1GC -Dfile.encoding=UTF-8"
ENV SPRING_PROFILES_ACTIVE=prod

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/auth-center.jar"]
