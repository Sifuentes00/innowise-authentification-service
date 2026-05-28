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

import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = {
        com.matvey.innowiseauthentificationservice.InnowiseAuthentificationServiceApplication.class,
        com.matvey.innowiseauthentificationservice.config.TestConfig.class
})
class AuthServiceTest {

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
        request.setRole(RoleType.USER);

        authService.register(request, testUserId);

        Optional<UserCredential> user = userCredentialRepository.findByEmail("test@example.com");
        assertTrue(user.isPresent());
        assertEquals(testUserId, user.get().getUserId());
        assertEquals("test@example.com", user.get().getEmail());
        assertNotNull(user.get().getPasswordHash());
        assertNotEquals("password123", user.get().getPasswordHash());
    }

    @Test
    void register_WithAdminRole_ShouldCreateAdminUser() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Admin");
        request.setSurname("User");
        request.setBirthDate(LocalDate.of(1990, 1, 1));
        request.setEmail("admin@example.com");
        request.setPassword("admin123");
        request.setRole(RoleType.ADMIN);

        authService.register(request, testUserId);

        Optional<UserCredential> user = userCredentialRepository.findByEmail("admin@example.com");
        assertTrue(user.isPresent());
        assertEquals(RoleType.ADMIN, user.get().getRole());
    }

    @Test
    void login_ShouldReturnTokens_WhenValidCredentials() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("login@example.com");
        registerRequest.setPassword("password123");
        registerRequest.setRole(RoleType.USER);

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
    void login_WithAdmin_ShouldReturnAdminToken() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Admin");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("adminlogin@example.com");
        registerRequest.setPassword("admin123");
        registerRequest.setRole(RoleType.ADMIN);

        authService.register(registerRequest, testUserId);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("adminlogin@example.com");
        loginRequest.setPassword("admin123");

        AuthResponse response = authService.login(loginRequest);

        assertEquals("ROLE_ADMIN", jwtUtil.extractRole(response.getAccessToken()));
    }

    @Test
    void login_ShouldFail_WhenInvalidCredentials() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test");
        registerRequest.setSurname("User");
        registerRequest.setBirthDate(LocalDate.of(1990, 1, 1));
        registerRequest.setEmail("invalid@example.com");
        registerRequest.setPassword("password123");
        registerRequest.setRole(RoleType.USER);

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
        registerRequest.setRole(RoleType.USER);

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

}
