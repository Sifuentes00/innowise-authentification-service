package com.matvey.innowiseauthentificationservice.config;

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
}
