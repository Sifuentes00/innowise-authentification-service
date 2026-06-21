package com.matvey.innowiseauthentificationservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.matvey.innowiseauthentificationservice.dto.AdminRegisterRequest;
import com.matvey.innowiseauthentificationservice.dto.AuthResponse;
import com.matvey.innowiseauthentificationservice.dto.LoginRequest;
import com.matvey.innowiseauthentificationservice.dto.RefreshRequest;
import com.matvey.innowiseauthentificationservice.dto.RegisterRequest;
import com.matvey.innowiseauthentificationservice.entity.UserCredential;
import com.matvey.innowiseauthentificationservice.enums.RoleType;
import com.matvey.innowiseauthentificationservice.repository.UserCredentialRepository;
import com.matvey.innowiseauthentificationservice.service.AuthService;
import com.matvey.innowiseauthentificationservice.util.JwtUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.LocalDate;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = {
        com.matvey.innowiseauthentificationservice.InnowiseAuthentificationServiceApplication.class
})
@ActiveProfiles("test")
@Testcontainers
class AuthControllerTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("innowise_authentification_service")
            .withUsername("app_user")
            .withPassword("app-password");

    @DynamicPropertySource
    static void postgresProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserCredentialRepository userCredentialRepository;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;
    private UUID testUserId;

    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());
        testUserId = UUID.randomUUID();
    }

    @AfterEach
    void cleanup() {
        userCredentialRepository.deleteAll();
    }

    @Test
    void login_ShouldReturnTokens_WhenValidCredentials() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("test@example.com");
        registerRequest.setPassword("password123");

        authService.createCredentials(registerRequest, testUserId);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password123");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists());
    }

    @Test
    void login_ShouldReturnUnauthorized_WhenInvalidEmail() throws Exception {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("nonexistent@example.com");
        loginRequest.setPassword("password123");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_ShouldReturnUnauthorized_WhenInvalidPassword() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("test@example.com");
        registerRequest.setPassword("password123");

        authService.createCredentials(registerRequest, testUserId);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("wrongpassword");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refresh_ShouldReturnNewTokens_WhenValidRefreshToken() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("refresh@example.com");
        registerRequest.setPassword("password123");

        authService.createCredentials(registerRequest, testUserId);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("refresh@example.com");
        loginRequest.setPassword("password123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        AuthResponse loginResponse = objectMapper.readValue(loginResult.getResponse().getContentAsString(), AuthResponse.class);

        RefreshRequest refreshRequest = new RefreshRequest();
        refreshRequest.setRefreshToken(loginResponse.getRefreshToken());

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists());
    }

    @Test
    void refresh_ShouldReturnUnauthorized_WhenInvalidRefreshToken() throws Exception {
        RefreshRequest refreshRequest = new RefreshRequest();
        refreshRequest.setRefreshToken("invalid.token.here");

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getPublicKey_ShouldReturnPublicKey() throws Exception {
        mockMvc.perform(get("/api/auth/public-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publicKey").exists())
                .andExpect(jsonPath("$.algorithm").value("RS256"));
    }

}
