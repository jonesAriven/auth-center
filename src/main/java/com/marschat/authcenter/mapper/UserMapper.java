package com.marschat.authcenter.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.marschat.authcenter.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper extends BaseMapper<User> {

    /**
     * 按用户名计数（**含软删行**）。
     * BaseMapper 的查询会被 @TableLogic 自动追加 deleted=0，
     * 而 uk_username 唯一索引不区分 deleted —— 软删行仍占用用户名，
     * 创建同名用户会撞唯一键（2026-09-12 实测 500）。创建前查重必须用本方法。
     */
    @Select("SELECT COUNT(1) FROM user WHERE username = #{username}")
    long countByUsernameIncludingDeleted(@Param("username") String username);
}
