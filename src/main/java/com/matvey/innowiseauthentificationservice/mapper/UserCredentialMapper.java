package com.matvey.innowiseauthentificationservice.mapper;

import com.matvey.innowiseauthentificationservice.dto.RegisterRequest;
import com.matvey.innowiseauthentificationservice.entity.UserCredential;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

import java.util.UUID;

@Mapper(componentModel = "spring")
public interface UserCredentialMapper {
    
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "userId", source = "userId")
    @Mapping(target = "passwordHash", source = "password")
    @Mapping(target = "role", source = "role")
    UserCredential toEntity(RegisterRequest registerRequest, UUID userId);
}
