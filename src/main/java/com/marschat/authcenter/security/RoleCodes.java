package com.marschat.authcenter.security;

/**
 * 平台角色 code 常量（唯一事实源）。
 *
 * <h3>为什么需要它</h3>
 * 改造前 {@code "superadmin"} 只以裸字符串散落在多处（UserDetailsServiceImpl 两处、
 * PermissionService 默认绑定一处、UserServiceImpl 常量一处），且 {@code sys_role} 表里
 * <b>根本没有 superadmin 这一行</b> —— 于是「改一个字段即全域提权」且 {@code sys_user_role}
 * 查不到痕迹，审计不可信。
 * <p>
 * 本类把三个平台角色 code 收敛为常量，配合 {@code DatabaseInitializer#seedSuperadminRole()}
 * 把 superadmin 真正落库（{@code scope='platform', client_id IS NULL}），使：
 * <ul>
 *   <li>字符串只有一处定义，改名不会漏改；</li>
 *   <li>角色必须存在才能被 {@code roleIdsByCodes(scope=platform)} 解析 —— 杜绝凭空提权；</li>
 *   <li>绑定进 {@code sys_user_role} —— 审计可查。</li>
 * </ul>
 */
public final class RoleCodes {

    /** 平台超级管理员（跨应用全权；code 与 user.role 字段同语义）。 */
    public static final String SUPERADMIN = "superadmin";

    /** 平台管理员。 */
    public static final String ADMIN = "admin";

    /** 平台普通用户（登录即可拥有的基线角色）。 */
    public static final String USER = "user";

    private RoleCodes() {
        // 常量类，禁止实例化
    }
}
