# language: zh-CN
# SOP V1.1 阶段2.5 强制要求：BDD 场景文件
# 模块：kb-auth 认证业务
# 覆盖业务流程：FLOW-01 登录认证闭环
Feature: 用户认证
  作为一个用户
  我想要登录系统
  以便访问我的知识库

  # ============ Happy Path ============

  Scenario: 正确账号密码登录成功
    Given 系统存在用户 "admin"，密码 "admin123"，状态为启用
    When 用户使用 "admin" 和 "admin123" 登录
    Then 返回有效的 accessToken 和 refreshToken
    And accessToken 有效期为 15 分钟
    And refreshToken 有效期为 7 天
    And 响应中不包含密码字段
    And 数据库记录一条 refresh_token

  Scenario: 刷新令牌成功
    Given 用户 "admin" 持有有效的 refresh token
    When 用户刷新令牌
    Then 返回新的 accessToken 和 refreshToken
    And 旧 refresh token 被删除
    And 新 refresh token 被写入数据库

  Scenario: 登出加入黑名单
    Given 用户 "admin" 持有有效的 access token
    When 用户登出
    Then access token 加入 JWT 黑名单
    And 黑名单记录过期时间与 token 一致

  # ============ 异常路径 ============

  Scenario: 错误密码登录失败
    Given 系统存在用户 "admin"
    When 用户使用 "admin" 和 "wrongpass" 登录
    Then 返回 401 错误码
    And 错误信息为 "用户名或密码错误"
    And 不生成任何 token

  Scenario: 用户不存在登录失败
    Given 系统不存在用户 "nonexistent"
    When 用户使用 "nonexistent" 和 "password" 登录
    Then 返回 401 错误码
    And 错误信息为 "用户名或密码错误"

  Scenario: 被禁用用户登录失败
    Given 系统存在用户 "disabled"，状态为禁用
    When 用户使用 "disabled" 和 "password" 登录
    Then 返回 401 错误码
    And 错误信息为 "账号已被禁用"

  Scenario: 重复刷新令牌幂等（修复 TooManyResults bug）
    Given 用户 "admin" 的 refresh token 在数据库中存在重复记录
    When 用户刷新令牌
    Then 返回最新的令牌对
    And 不抛出 TooManyResultsException

  # ============ 边界路径 ============

  Scenario: 无效 token 登出不报错
    Given 用户持有无效的 token "invalid-token"
    When 用户登出
    Then 不抛出异常
    And 不写入黑名单

  Scenario: 传入空用户名登录失败
    Given 系统存在用户 "admin"
    When 用户使用 "" 和 "admin123" 登录
    Then 返回 400 错误码
    And 不查询数据库

  Scenario: 密码为空登录失败
    Given 系统存在用户 "admin"
    When 用户使用 "admin" 和 "" 登录
    Then 返回 400 错误码
    And 错误信息包含 "密码"

  Scenario: 过期 refresh token 刷新失败
    Given 用户 "admin" 持有已过期的 refresh token
    When 用户刷新令牌
    Then 返回 401 错误码
    And 错误信息为 "refresh token 已过期"

  Scenario: 篡改 refresh token 刷新失败
    Given 用户持有被篡改的 refresh token
    When 用户刷新令牌
    Then 返回 401 错误码
    And 不生成新令牌对
