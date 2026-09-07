# language: zh-CN
# SOP V1.1 阶段2.5 强制要求：BDD 场景文件
# 模块：kb-auth 认证业务
# 覆盖业务流程：FLOW-01 登录认证闭环
功能: 用户认证
  作为一个用户
  我想要登录系统
  以便访问我的知识库

  # ============ Happy Path ============

  场景: 正确账号密码登录成功
    假如 系统存在用户 "admin"，密码 "admin123"，状态为启用
    当 用户使用 "admin" 和 "admin123" 登录
    那么 返回有效的 accessToken 和 refreshToken
    而且 accessToken 有效期为 15 分钟
    而且 refreshToken 有效期为 7 天
    而且 响应中不包含密码字段
    而且 数据库记录一条 refresh_token

  场景: 刷新令牌成功
    假如 用户 "admin" 持有有效的 refresh token
    当 用户刷新令牌
    那么 返回新的 accessToken 和 refreshToken
    而且 旧 refresh token 被删除
    而且 新 refresh token 被写入数据库

  场景: 登出加入黑名单
    假如 用户 "admin" 持有有效的 access token
    当 用户登出
    那么 access token 加入 JWT 黑名单
    而且 黑名单记录过期时间与 token 一致

  # ============ 异常路径 ============

  场景: 错误密码登录失败
    假如 系统存在用户 "admin"
    当 用户使用 "admin" 和 "wrongpass" 登录
    那么 返回 401 错误码
    而且 错误信息为 "用户名或密码错误"
    而且 不生成任何 token

  场景: 用户不存在登录失败
    假如 系统不存在用户 "nonexistent"
    当 用户使用 "nonexistent" 和 "password" 登录
    那么 返回 401 错误码
    而且 错误信息为 "用户名或密码错误"

  场景: 被禁用用户登录失败
    假如 系统存在用户 "disabled"，状态为禁用
    当 用户使用 "disabled" 和 "password" 登录
    那么 返回 401 错误码
    而且 错误信息为 "账号已被禁用"

  场景: 重复刷新令牌幂等（修复 TooManyResults bug）
    假如 用户 "admin" 的 refresh token 在数据库中存在重复记录
    当 用户刷新令牌
    那么 返回最新的令牌对
    而且 不抛出 TooManyResultsException

  # ============ 边界路径 ============

  场景: 无效 token 登出不报错
    假如 用户持有无效的 token "invalid-token"
    当 用户登出
    那么 不抛出异常
    而且 不写入黑名单

  场景: 传入空用户名登录失败
    假如 系统存在用户 "admin"
    当 用户使用 "" 和 "admin123" 登录
    那么 返回 400 错误码
    而且 不查询数据库

  场景: 密码为空登录失败
    假如 系统存在用户 "admin"
    当 用户使用 "admin" 和 "" 登录
    那么 返回 400 错误码
    而且 错误信息包含 "密码"

  场景: 过期 refresh token 刷新失败
    假如 用户 "admin" 持有已过期的 refresh token
    当 用户刷新令牌
    那么 返回 401 错误码
    而且 错误信息为 "refresh token 已过期"

  场景: 篡改 refresh token 刷新失败
    假如 用户持有被篡改的 refresh token
    当 用户刷新令牌
    那么 返回 401 错误码
    而且 不生成新令牌对
