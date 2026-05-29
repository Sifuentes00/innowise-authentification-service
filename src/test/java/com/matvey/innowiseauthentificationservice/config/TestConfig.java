package com.matvey.innowiseauthentificationservice.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.matvey.innowiseauthentificationservice.client.UserServiceClient;
import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@TestConfiguration
public class TestConfig {

    @Bean
    public UserServiceClient userServiceClient() {
        return Mockito.mock(UserServiceClient.class);
    }

    @Bean
    public String jwtExpiration() {
        return "900000";
    }

    @Bean
    public String jwtRefreshExpiration() {
        return "604800000";
    }

    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        return mapper;
    }
}
