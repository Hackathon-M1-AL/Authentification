package com.esgi.spring.security.postgresql.mapper;

import com.esgi.spring.security.postgresql.payload.response.JwtErrorDTO;
import com.esgi.spring.security.postgresql.utils.exception.SecurityException;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

@Mapper(componentModel = "spring")
public interface JwtErrorMapper {
    public JwtErrorMapper INSTANCE = Mappers.getMapper(JwtErrorMapper.class);

    @Mapping(target = "status", source = "httpStatus")
    JwtErrorDTO toDto(SecurityException e);
}
