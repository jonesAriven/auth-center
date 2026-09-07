package com.marschat.authcenter.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.marschat.authcenter.entity.ApiToken;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface ApiTokenMapper extends BaseMapper<ApiToken> {
}
