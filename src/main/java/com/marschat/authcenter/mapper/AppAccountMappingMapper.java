package com.marschat.authcenter.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.marschat.authcenter.entity.AppAccountMapping;
import org.apache.ibatis.annotations.Mapper;

/**
 * 应用账号映射 Mapper。
 *
 * <p>读多写少的批量场景（上报同步、列表查询、按用户/按应用聚合）统一走
 * {@code AccountMappingService} 内的 JdbcTemplate，本 Mapper 仅提供按主键的
 * 标准 CRUD 能力（与其它实体保持一致）。
 */
@Mapper
public interface AppAccountMappingMapper extends BaseMapper<AppAccountMapping> {
}
