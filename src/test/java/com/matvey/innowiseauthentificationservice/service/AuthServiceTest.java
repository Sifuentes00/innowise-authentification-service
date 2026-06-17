package com.matvey.innowiseauthentificationservice.service;

import com.matvey.innowiseauthentificationservice.dto.AuthResponse;
import com.matvey.innowiseauthentificationservice.dto.LoginRequest;
import com.matvey.innowiseauthentificationservice.dto.RefreshRequest;
import com.matvey.innowiseauthentificationservice.dto.RegisterRequest;
import com.matvey.innowiseauthentificationservice.dto.ValidateRequest;
import com.matvey.innowiseauthentificationservice.dto.ValidateResponse;
import com.matvey.innowiseauthentificationservice.entity.UserCredential;
import com.matvey.innowiseauthentificationservice.enums.RoleType;
import com.matvey.innowiseauthentificationservice.repository.UserCredentialRepository;
import com.matvey.innowiseauthentificationservice.util.JwtUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.transaction.TestTransaction;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = {
        com.matvey.innowiseauthentificationservice.InnowiseAuthentificationServiceApplication.class,
        com.matvey.innowiseauthentificationservice.config.TestConfig.class
})
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "jwt.keys-path=/tmp/test-keys/"
})
@Testcontainers
class AuthServiceTest {

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
    private AuthService authService;

    @Autowired
    private UserCredentialRepository userCredentialRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private com.matvey.innowiseauthentificationservice.repository.RefreshTokenRepository refreshTokenRepository;

    private UUID testUserId;

    @BeforeEach
    void setup() {
        testUserId = UUID.randomUUID();
    }

    @AfterEach
    void cleanup() {
        refreshTokenRepository.deleteAll();
        userCredentialRepository.deleteAll();
    }

    @Test
    void register_ShouldCreateUserCredential() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Test");
        request.setSurname("User");
        request.setBirthDate(LocalDate.of(1990, 1, 1));
        request.setEmail("test@example.com");
        request.setPassword("password123");

        authService.register(request, testUserId);

        Optional<UserCredential> user = userCredentialRepository.findByEmail("test@example.com");
        assertTrue(user.isPresent());
        assertEquals(testUserId, user.get().getUserId());
        assertEquals("test@example.com", user.get().getEmail());
        assertNotNull(user.get().getPasswordHash());
        assertNotEquals("password123", user.get().getPasswordHash());
        assertEquals(RoleType.USER, user.get().getRole());
    }

    @Test
    void register_ShouldCreateUserWithUserRole() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Admin");
        request.setSurname("User");
        request.setBirthDate(LocalDate.of(1990, 1, 1));
        request.setEmail("admin@example.com");
        request.setPassword("admin123");

        authService.register(request, testUserId);

        Optional<UserCredential> user = userCredentialRepository.findByEmail("admin@example.com");
        assertTrue(user.isPresent());
        assertEquals(RoleType.USER, user.get().getRole());
    }

    @Test
    void login_ShouldReturnTokens_WhenValidCredentials() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("login@example.com");
        registerRequest.setPassword("password123");

        authService.register(registerRequest, testUserId);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("login@example.com");
        loginRequest.setPassword("password123");

        AuthResponse response = authService.login(loginRequest);

        assertNotNull(response.getAccessToken());
        assertNotNull(response.getRefreshToken());
        assertEquals(testUserId, jwtUtil.extractUserId(response.getAccessToken()));
        assertEquals("ROLE_USER", jwtUtil.extractRole(response.getAccessToken()));
    }

    @Test
    void login_ShouldReturnUserToken() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Admin");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("adminlogin@example.com");
        registerRequest.setPassword("admin123");

        authService.register(registerRequest, testUserId);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("adminlogin@example.com");
        loginRequest.setPassword("admin123");

        AuthResponse response = authService.login(loginRequest);

        assertEquals("ROLE_USER", jwtUtil.extractRole(response.getAccessToken()));
    }

    @Test
    void login_ShouldFail_WhenInvalidCredentials() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("invalid@example.com");
        registerRequest.setPassword("password123");

        authService.register(registerRequest, testUserId);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("invalid@example.com");
        loginRequest.setPassword("wrongpassword");

        assertThrows(RuntimeException.class, () -> authService.login(loginRequest));
    }

    @Test
    void validate_ShouldReturnTrue_WhenValidToken() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("validate@example.com");
        registerRequest.setPassword("password123");

        authService.register(registerRequest, testUserId);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("validate@example.com");
        loginRequest.setPassword("password123");

        AuthResponse authResponse = authService.login(loginRequest);

        ValidateRequest validateRequest = new ValidateRequest();
        validateRequest.setToken(authResponse.getAccessToken());

        ValidateResponse response = authService.validate(validateRequest);

        assertTrue(response.isValid());
        assertEquals(testUserId.toString(), response.getUserId());
        assertEquals("ROLE_USER", response.getRole());
    }

    @Test
    void refresh_ShouldReturnNewTokens_WhenValidRefreshToken() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("refresh@example.com");
        registerRequest.setPassword("password123");

        authService.register(registerRequest, testUserId);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("refresh@example.com");
        loginRequest.setPassword("password123");

        AuthResponse authResponse = authService.login(loginRequest);
        String originalAccessToken = authResponse.getAccessToken();

        RefreshRequest refreshRequest = new RefreshRequest();
        refreshRequest.setRefreshToken(authResponse.getRefreshToken());

        AuthResponse refreshResponse = authService.refresh(refreshRequest);

        assertNotNull(refreshResponse.getAccessToken());
        assertNotNull(refreshResponse.getRefreshToken());
        assertNotEquals(originalAccessToken, refreshResponse.getAccessToken());
    }

    @Test
    @Transactional
    void login_ShouldRevokeOldRefreshTokens() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("revoke@example.com");
        registerRequest.setPassword("password123");

        authService.register(registerRequest, testUserId);

        LoginRequest loginRequest1 = new LoginRequest();
        loginRequest1.setEmail("revoke@example.com");
        loginRequest1.setPassword("password123");

        AuthResponse authResponse1 = authService.login(loginRequest1);
        String firstRefreshToken = authResponse1.getRefreshToken();

        LoginRequest loginRequest2 = new LoginRequest();
        loginRequest2.setEmail("revoke@example.com");
        loginRequest2.setPassword("password123");

        AuthResponse authResponse2 = authService.login(loginRequest2);

        RefreshRequest refreshRequest = new RefreshRequest();
        refreshRequest.setRefreshToken(firstRefreshToken);

        assertThrows(com.matvey.innowiseauthentificationservice.exception.InvalidRefreshTokenException.class,
                () -> authService.refresh(refreshRequest));
    }

    @Test
    void validate_ShouldRejectRefreshTokens() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("refreshvalidate@example.com");
        registerRequest.setPassword("password123");

        authService.register(registerRequest, testUserId);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("refreshvalidate@example.com");
        loginRequest.setPassword("password123");

        AuthResponse authResponse = authService.login(loginRequest);

        ValidateRequest validateRequest = new ValidateRequest();
        validateRequest.setToken(authResponse.getRefreshToken());

        ValidateResponse response = authService.validate(validateRequest);

        assertFalse(response.isValid());
        assertNull(response.getUserId());
        assertNull(response.getRole());
    }

}
