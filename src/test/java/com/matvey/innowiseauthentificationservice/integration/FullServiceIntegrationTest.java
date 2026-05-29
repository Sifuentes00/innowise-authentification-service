package com.matvey.innowiseauthentificationservice.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.matvey.innowiseauthentificationservice.dto.AuthResponse;
import com.matvey.innowiseauthentificationservice.dto.LoginRequest;
import com.matvey.innowiseauthentificationservice.dto.RefreshRequest;
import com.matvey.innowiseauthentificationservice.dto.RegisterRequest;
import com.matvey.innowiseauthentificationservice.dto.ValidateRequest;
import com.matvey.innowiseauthentificationservice.dto.ValidateResponse;
import com.matvey.innowiseauthentificationservice.config.TestConfig;
import com.matvey.innowiseauthentificationservice.entity.UserCredential;
import com.matvey.innowiseauthentificationservice.repository.RefreshTokenRepository;
import com.matvey.innowiseauthentificationservice.repository.UserCredentialRepository;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.annotation.DirtiesContext;
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

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK, classes = {TestConfig.class})
@Testcontainers
@TestPropertySource(properties = {
        "spring.liquibase.enabled=true",
        "user.service.enabled=false",
        "user.service.url=http://localhost:8080",
        "cors.allowed-origins=http://localhost:8080",
        "jwt.expiration=900000",
        "jwt.refresh-expiration=604800000"
})
class FullServiceIntegrationTest {

    @Container
    static PostgreSQLContainer<?> authPostgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("innowise_authentification_service")
            .withUsername("app_user")
            .withPassword("app-password");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", authPostgres::getJdbcUrl);
        registry.add("spring.datasource.username", authPostgres::getUsername);
        registry.add("spring.datasource.password", authPostgres::getPassword);
    }

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserCredentialRepository userCredentialRepository;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
        refreshTokenRepository.deleteAll();
        userCredentialRepository.deleteAll();
    }

    @Test
    @DisplayName("Register new user - should create user in Auth Service")
    void testRegisterUser() throws Exception {
        UUID userId = UUID.randomUUID();
        String uniqueEmail = "test" + System.currentTimeMillis() + "@example.com";
        RegisterRequest request = new RegisterRequest();
        request.setName("Integration");
        request.setSurname("Test");
        request.setBirthDate(LocalDate.of(1990, 1, 1));
        request.setEmail(uniqueEmail);
        request.setPassword("testPassword123");
        request.setRole(com.matvey.innowiseauthentificationservice.enums.RoleType.USER);

        mockMvc.perform(post("/api/auth/register/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        UserCredential user = userCredentialRepository.findByEmail(uniqueEmail).orElse(null);
        assertNotNull(user);
        assertEquals(uniqueEmail, user.getEmail());
    }

    @Test
    @DisplayName("Login with registered credentials - should return valid tokens")
    void testLoginUser() throws Exception {
        UUID userId = UUID.randomUUID();
        String uniqueEmail = "login" + System.currentTimeMillis() + "@example.com";
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Integration");
        registerRequest.setSurname("Test");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail(uniqueEmail);
        registerRequest.setPassword("testPassword123");
        registerRequest.setRole(com.matvey.innowiseauthentificationservice.enums.RoleType.USER);

        mockMvc.perform(post("/api/auth/register/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        LoginRequest request = new LoginRequest();
        request.setEmail(uniqueEmail);
        request.setPassword("testPassword123");

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn();

        AuthResponse response = objectMapper.readValue(result.getResponse().getContentAsString(), AuthResponse.class);
        assertNotNull(response.getAccessToken());
        assertNotNull(response.getRefreshToken());
    }

    @Test
    @DisplayName("Validate access token - should return user info")
    void testValidateToken() throws Exception {
        UUID userId = UUID.randomUUID();
        String uniqueEmail = "validate" + System.currentTimeMillis() + "@example.com";
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Integration");
        registerRequest.setSurname("Test");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail(uniqueEmail);
        registerRequest.setPassword("testPassword123");
        registerRequest.setRole(com.matvey.innowiseauthentificationservice.enums.RoleType.USER);

        mockMvc.perform(post("/api/auth/register/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(uniqueEmail);
        loginRequest.setPassword("testPassword123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        AuthResponse loginResponse = objectMapper.readValue(loginResult.getResponse().getContentAsString(), AuthResponse.class);

        ValidateRequest validateRequest = new ValidateRequest();
        validateRequest.setToken(loginResponse.getAccessToken());

        MvcResult result = mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validateRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.userId").exists())
                .andExpect(jsonPath("$.role").exists())
                .andReturn();

        ValidateResponse response = objectMapper.readValue(result.getResponse().getContentAsString(), ValidateResponse.class);
        assertTrue(response.isValid());
        assertNotNull(response.getUserId());
        assertNotNull(response.getRole());
    }

    @Test
    @DisplayName("Refresh access token - should return new tokens")
    void testRefreshToken() throws Exception {
        UUID userId = UUID.randomUUID();
        String uniqueEmail = "refresh" + System.currentTimeMillis() + "@example.com";
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Integration");
        registerRequest.setSurname("Test");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail(uniqueEmail);
        registerRequest.setPassword("testPassword123");
        registerRequest.setRole(com.matvey.innowiseauthentificationservice.enums.RoleType.USER);

        mockMvc.perform(post("/api/auth/register/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(uniqueEmail);
        loginRequest.setPassword("testPassword123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        AuthResponse loginResponse = objectMapper.readValue(loginResult.getResponse().getContentAsString(), AuthResponse.class);
        String originalAccessToken = loginResponse.getAccessToken();

        RefreshRequest refreshRequest = new RefreshRequest();
        refreshRequest.setRefreshToken(loginResponse.getRefreshToken());

        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn();

        AuthResponse response = objectMapper.readValue(result.getResponse().getContentAsString(), AuthResponse.class);
        assertNotNull(response.getAccessToken());
        assertNotNull(response.getRefreshToken());

        String newAccessToken = response.getAccessToken();
        assertNotEquals(originalAccessToken, newAccessToken);
    }

    @Test
    @DisplayName("Validate new access token - should work with refreshed token")
    void testValidateNewToken() throws Exception {
        UUID userId = UUID.randomUUID();
        String uniqueEmail = "validatenew" + System.currentTimeMillis() + "@example.com";
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Integration");
        registerRequest.setSurname("Test");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail(uniqueEmail);
        registerRequest.setPassword("testPassword123");
        registerRequest.setRole(com.matvey.innowiseauthentificationservice.enums.RoleType.USER);

        mockMvc.perform(post("/api/auth/register/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(uniqueEmail);
        loginRequest.setPassword("testPassword123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        AuthResponse loginResponse = objectMapper.readValue(loginResult.getResponse().getContentAsString(), AuthResponse.class);

        RefreshRequest refreshRequest = new RefreshRequest();
        refreshRequest.setRefreshToken(loginResponse.getRefreshToken());

        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andReturn();

        AuthResponse refreshResponse = objectMapper.readValue(refreshResult.getResponse().getContentAsString(), AuthResponse.class);

        ValidateRequest validateRequest = new ValidateRequest();
        validateRequest.setToken(refreshResponse.getAccessToken());

        MvcResult result = mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validateRequest)))
                .andExpect(status().isOk())
                .andReturn();

        ValidateResponse response = objectMapper.readValue(result.getResponse().getContentAsString(), ValidateResponse.class);
        assertTrue(response.isValid());
    }

    @Test
    @DisplayName("Login with wrong password - should fail")
    void testLoginWithWrongPassword() throws Exception {
        UUID userId = UUID.randomUUID();
        String uniqueEmail = "wrongpass" + System.currentTimeMillis() + "@example.com";
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Integration");
        registerRequest.setSurname("Test");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail(uniqueEmail);
        registerRequest.setPassword("testPassword123");
        registerRequest.setRole(com.matvey.innowiseauthentificationservice.enums.RoleType.USER);

        mockMvc.perform(post("/api/auth/register/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        LoginRequest request = new LoginRequest();
        request.setEmail(uniqueEmail);
        request.setPassword("wrongPassword");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Validate invalid token - should return valid:false")
    void testValidateInvalidToken() throws Exception {
        ValidateRequest validateRequest = new ValidateRequest();
        validateRequest.setToken("invalid.token.here");

        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validateRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
    }

    @Test
    @DisplayName("Register duplicate email - should fail")
    void testRegisterDuplicateEmail() throws Exception {
        UUID userId1 = UUID.randomUUID();
        String uniqueEmail = "duplicate" + System.currentTimeMillis() + "@example.com";
        RegisterRequest request1 = new RegisterRequest();
        request1.setName("Integration");
        request1.setSurname("Test");
        request1.setBirthDate(LocalDate.of(1990, 1, 1));
        request1.setEmail(uniqueEmail);
        request1.setPassword("testPassword123");
        request1.setRole(com.matvey.innowiseauthentificationservice.enums.RoleType.USER);

        mockMvc.perform(post("/api/auth/register/" + userId1)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request1)))
                .andExpect(status().isCreated());

        UUID userId2 = UUID.randomUUID();
        RegisterRequest request2 = new RegisterRequest();
        request2.setName("Integration");
        request2.setSurname("Test");
        request2.setBirthDate(LocalDate.of(1990, 1, 1));
        request2.setEmail(uniqueEmail);
        request2.setPassword("anotherPassword");
        request2.setRole(com.matvey.innowiseauthentificationservice.enums.RoleType.USER);

        mockMvc.perform(post("/api/auth/register/" + userId2)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request2)))
                .andExpect(status().isConflict());
    }
}