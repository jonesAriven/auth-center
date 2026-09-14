package com.marschat.authcenter.controller;

import com.marschat.common.result.Result;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 跨应用授权矩阵（Phase 8 · 中心侧「统一认证中心」核心新能力）。
 *
 * <h3>为什么需要它</h3>
 * 良哥的初衷之一是「<b>哪些账号有哪些系统的权限</b>」。此前这件事只能**逐应用进、逐用户点**
 * （每个应用的「应用角色」弹窗一次只看一个用户 × 一个应用），
 * 完全没有一处可以横向对比的总览。
 *
 * <p>本端点把「用户 × 应用」压成**一张矩阵**：行=用户，列=各应用，单元格=该用户在该应用的角色。
 * 一屏即可回答「某人有哪些系统的权限」「某系统有哪些人被授权」，并支持点击单元格直接改绑
 * （复用既有 {@code PUT /admin/users/{userId}/client-roles?client=}）。
 *
 * <h3>契约</h3>
 * <pre>
 * GET /admin/authorization-matrix?keyword=&page=&size=
 * {
 *   "total": 20, "page": 1, "size": 20,
 *   "clients": [{"clientId":"marschat-kbops","name":"运维后台 kb-ops"}],
 *   "records": [{
 *     "userId": 1, "username": "admin", "nickname": "超级管理员",
 *     "email": "marschat@163.com", "globalRole": "superadmin", "status": 1,
 *     "apps": {"marschat-kbops":[{"id":8,"code":"user","name":"普通用户"}], "marschat-kbweb":[]}
 *   }]
 * }
 * </pre>
 *
 * <p>鉴权与其余 {@code /admin/**} 一致：Bearer + {@code ROLE_ADMIN}。
 */
@Slf4j
@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminAuthzMatrixController {

    private final JdbcTemplate jdbcTemplate;

    @GetMapping("/authorization-matrix")
    public Result<Map<String, Object>> matrix(
            @RequestParam(required = false) String keyword,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size) {

        // ① 列：全部启用中的应用（前端按此动态渲染表头，新增应用零前端改动）
        List<Map<String, Object>> clients = jdbcTemplate.queryForList(
                "SELECT client_id AS clientId, COALESCE(NULLIF(name, ''), client_id) AS name "
                        + "FROM sys_app_client WHERE status = 1 ORDER BY client_id");

        // ② 行：统一身份（分页 + 关键字）
        StringBuilder where = new StringBuilder(" FROM user WHERE deleted = 0");
        List<Object> args = new ArrayList<>();
        if (keyword != null && !keyword.isBlank()) {
            where.append(" AND (username LIKE ? OR email LIKE ? OR nickname LIKE ?)");
            String like = "%" + keyword + "%";
            args.add(like);
            args.add(like);
            args.add(like);
        }
        Long totalObj = jdbcTemplate.queryForObject("SELECT COUNT(*)" + where, Long.class, args.toArray());
        long total = totalObj == null ? 0L : totalObj;

        List<Object> pageArgs = new ArrayList<>(args);
        pageArgs.add(size);
        pageArgs.add((page - 1) * size);
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "SELECT id AS userId, username, nickname, email, role AS globalRole, status "
                        + where + " ORDER BY created_at DESC LIMIT ? OFFSET ?",
                pageArgs.toArray());

        // ③ 单元格：本页用户在各应用的角色（client 级角色；platform 角色只体现在 globalRole 列）
        Map<Long, Map<String, List<Map<String, Object>>>> cellMap = new HashMap<>();
        if (!rows.isEmpty()) {
            String idList = rows.stream()
                    .map(r -> String.valueOf(((Number) r.get("userId")).longValue()))
                    .collect(Collectors.joining(","));
            List<Map<String, Object>> bindings = jdbcTemplate.queryForList(
                    "SELECT ur.user_id AS userId, r.client_id AS clientId, r.id AS id, r.code AS code, r.name AS name "
                            + "FROM sys_user_role ur JOIN sys_role r ON r.id = ur.role_id "
                            + "WHERE r.scope = 'client' AND r.client_id IS NOT NULL "
                            + "AND ur.user_id IN (" + idList + ") ORDER BY r.code");
            for (Map<String, Object> b : bindings) {
                Long uid = ((Number) b.get("userId")).longValue();
                String cid = String.valueOf(b.get("clientId"));
                Map<String, Object> role = new LinkedHashMap<>();
                role.put("id", b.get("id"));
                role.put("code", b.get("code"));
                role.put("name", b.get("name"));
                cellMap.computeIfAbsent(uid, k -> new HashMap<>())
                        .computeIfAbsent(cid, k -> new ArrayList<>())
                        .add(role);
            }
        }
        for (Map<String, Object> r : rows) {
            Long uid = ((Number) r.get("userId")).longValue();
            // apps 只放有绑定的应用；前端对未出现的 client 渲染「未授权」
            r.put("apps", cellMap.getOrDefault(uid, Map.of()));
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("total", total);
        data.put("page", page);
        data.put("size", size);
        data.put("clients", clients);
        data.put("records", rows);
        return Result.ok(data);
    }
}
