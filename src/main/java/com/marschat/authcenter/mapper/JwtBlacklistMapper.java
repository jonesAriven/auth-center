package com.marschat.authcenter.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.marschat.authcenter.entity.JwtBlacklist;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface JwtBlacklistMapper extends BaseMapper<JwtBlacklist> {
}
