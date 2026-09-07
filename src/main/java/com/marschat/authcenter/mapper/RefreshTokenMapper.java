package com.marschat.authcenter.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.marschat.authcenter.entity.RefreshToken;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface RefreshTokenMapper extends BaseMapper<RefreshToken> {
}
