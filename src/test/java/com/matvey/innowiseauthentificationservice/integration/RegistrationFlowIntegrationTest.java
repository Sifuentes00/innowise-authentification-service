package com.matvey.innowiseauthentificationservice.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.matvey.innowiseauthentificationservice.dto.AdminRegisterRequest;
import com.matvey.innowiseauthentificationservice.dto.AuthResponse;
import com.matvey.innowiseauthentificationservice.dto.LoginRequest;
import com.matvey.innowiseauthentificationservice.dto.RefreshRequest;
import com.matvey.innowiseauthentificationservice.dto.RegisterRequest;
import com.matvey.innowiseauthentificationservice.entity.UserCredential;
import com.matvey.innowiseauthentificationservice.enums.RoleType;
import com.matvey.innowiseauthentificationservice.repository.UserCredentialRepository;
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
class RegistrationFlowIntegrationTest {

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
    void completeUserRegistrationFlow_ShouldSucceed() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("user@example.com");
        registerRequest.setPassword("password123");

        mockMvc.perform(post("/internal/credentials/" + testUserId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        UserCredential user = userCredentialRepository.findByEmail("user@example.com").orElse(null);
        assertNotNull(user);
        assertEquals(testUserId, user.getUserId());
        assertEquals("user@example.com", user.getEmail());
        assertEquals(RoleType.USER, user.getRole());

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("user@example.com");
        loginRequest.setPassword("password123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn();

        AuthResponse loginResponse = objectMapper.readValue(loginResult.getResponse().getContentAsString(), AuthResponse.class);
        assertEquals(testUserId, jwtUtil.extractUserId(loginResponse.getAccessToken()));
        assertEquals("ROLE_USER", jwtUtil.extractRole(loginResponse.getAccessToken()));

        RefreshRequest refreshRequest = new RefreshRequest();
        refreshRequest.setRefreshToken(loginResponse.getRefreshToken());

        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn();

        AuthResponse refreshResponse = objectMapper.readValue(refreshResult.getResponse().getContentAsString(), AuthResponse.class);
        assertEquals(testUserId, jwtUtil.extractUserId(refreshResponse.getAccessToken()));
        assertEquals("ROLE_USER", jwtUtil.extractRole(refreshResponse.getAccessToken()));
        assertNotEquals(loginResponse.getAccessToken(), refreshResponse.getAccessToken());

        mockMvc.perform(delete("/internal/credentials/" + testUserId))
                .andExpect(status().isNoContent());

        UserCredential deletedUser = userCredentialRepository.findByEmail("user@example.com").orElse(null);
        assertNull(deletedUser);
    }

    @Test
    void completeAdminRegistrationFlow_ShouldSucceed() throws Exception {
        AdminRegisterRequest adminRegisterRequest = new AdminRegisterRequest();
        adminRegisterRequest.setName("Admin");
        adminRegisterRequest.setSurname("User");
        adminRegisterRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        adminRegisterRequest.setEmail("admin@example.com");
        adminRegisterRequest.setPassword("admin123");
        adminRegisterRequest.setRole(RoleType.ADMIN);

        mockMvc.perform(post("/internal/admin-credentials/" + testUserId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(adminRegisterRequest)))
                .andExpect(status().isCreated());

        UserCredential admin = userCredentialRepository.findByEmail("admin@example.com").orElse(null);
        assertNotNull(admin);
        assertEquals(testUserId, admin.getUserId());
        assertEquals("admin@example.com", admin.getEmail());
        assertEquals(RoleType.ADMIN, admin.getRole());

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("admin@example.com");
        loginRequest.setPassword("admin123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn();

        AuthResponse loginResponse = objectMapper.readValue(loginResult.getResponse().getContentAsString(), AuthResponse.class);
        assertEquals(testUserId, jwtUtil.extractUserId(loginResponse.getAccessToken()));
        assertEquals("ROLE_ADMIN", jwtUtil.extractRole(loginResponse.getAccessToken()));

        mockMvc.perform(delete("/internal/credentials/" + testUserId))
                .andExpect(status().isNoContent());

        UserCredential deletedAdmin = userCredentialRepository.findByEmail("admin@example.com").orElse(null);
        assertNull(deletedAdmin);
    }

    @Test
    void registrationWithRollback_ShouldDeleteCredentials() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("rollback@example.com");
        registerRequest.setPassword("password123");

        mockMvc.perform(post("/internal/credentials/" + testUserId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        assertNotNull(userCredentialRepository.findByEmail("rollback@example.com").orElse(null));

        mockMvc.perform(delete("/internal/credentials/" + testUserId))
                .andExpect(status().isNoContent());

        assertNull(userCredentialRepository.findByEmail("rollback@example.com").orElse(null));
    }

}
