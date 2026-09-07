#!/usr/bin/env bash
# auth-center 邮箱验证码 + 忘记密码 集成自测脚本（M7）
# 前置：auth-center 已启动并连接 MySQL/Redis；SMTP 环境变量已配置（否则邮件不实际发出，但不影响流程）。
# 部署由主线程统一执行，本脚本仅演示 curl 序列，本地可用 Git Bash 运行。
set -euo pipefail

BASE="http://localhost:8085"
EMAIL="testuser@example.com"
NEW_PWD="NewPass@123"

echo "== 1) 触发忘记密码（发码，防枚举：无论邮箱是否存在均返回 200）=="
curl -s -X POST "$BASE/auth/forgot-password" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\"}"
echo

echo "== 2) 从 Redis 取码（bizType=RESET_PASSWORD，key 形如 auth:mail:code:RESET_PASSWORD:<email>）=="
CODE=$(docker exec "$(docker ps -qf name=redis)" redis-cli GET "auth:mail:code:RESET_PASSWORD:$EMAIL")
echo "code=$CODE"

echo "== 3) 重置密码 =="
curl -s -X POST "$BASE/auth/reset-password" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"code\":\"$CODE\",\"newPassword\":\"$NEW_PWD\"}"
echo

echo "== 4a) 用新密码登录（应成功）=="
curl -s -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$EMAIL\",\"password\":\"$NEW_PWD\"}"
echo

echo "== 4b) 用旧密码登录（应失败，提示用户名或密码错误）=="
curl -s -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$EMAIL\",\"password\":\"OldPass@123\"}"
echo

echo "== 5) 验证验证码一次性（再重置应报错，凭证已删除）=="
curl -s -X POST "$BASE/auth/reset-password" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"code\":\"$CODE\",\"newPassword\":\"x\"}"
echo
