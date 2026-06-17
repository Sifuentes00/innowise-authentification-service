package com.matvey.innowiseauthentificationservice.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "jwt.keys-path=/tmp/test-keys/"
})
@Testcontainers
class JwtUtilTest {

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

    @Value("${jwt.keys-path}")
    private String keysPath;

    @Autowired
    private JwtUtil jwtUtil;

    @AfterEach
    void cleanupKeys() throws IOException {
        Path keysDir = Paths.get(keysPath);
        if (Files.exists(keysDir)) {
            Files.walk(keysDir)
                    .sorted((a, b) -> -a.compareTo(b))
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                        }
                    });
        }
    }

    @Test
    void generateAccessToken_ShouldReturnValidToken() {
        UUID userId = UUID.randomUUID();
        String role = "USER";

        String token = jwtUtil.generateAccessToken(userId, role);

        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void generateAccessToken_WithAdminRole_ShouldReturnValidToken() {
        UUID userId = UUID.randomUUID();
        String role = "ADMIN";

        String token = jwtUtil.generateAccessToken(userId, role);

        assertNotNull(token);
        assertEquals("ROLE_ADMIN", jwtUtil.extractRole(token));
    }

    @Test
    void generateRefreshToken_ShouldReturnValidToken() {
        UUID userId = UUID.randomUUID();

        String token = jwtUtil.generateRefreshToken(userId);

        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void extractUserId_ShouldReturnCorrectUserId() {
        UUID userId = UUID.randomUUID();
        String role = "USER";

        String token = jwtUtil.generateAccessToken(userId, role);
        UUID extractedUserId = jwtUtil.extractUserId(token);

        assertEquals(userId, extractedUserId);
    }

    @Test
    void extractRole_ShouldReturnCorrectRole() {
        UUID userId = UUID.randomUUID();
        String role = "ADMIN";

        String token = jwtUtil.generateAccessToken(userId, role);
        String extractedRole = jwtUtil.extractRole(token);

        assertEquals("ROLE_ADMIN", extractedRole);
    }

    @Test
    void extractRole_WithUserRole_ShouldReturnROLE_USER() {
        UUID userId = UUID.randomUUID();
        String role = "USER";

        String token = jwtUtil.generateAccessToken(userId, role);
        String extractedRole = jwtUtil.extractRole(token);

        assertEquals("ROLE_USER", extractedRole);
    }

    @Test
    void validateToken_ShouldReturnTrue_ForValidToken() {
        UUID userId = UUID.randomUUID();
        String role = "USER";

        String token = jwtUtil.generateAccessToken(userId, role);
        boolean isValid = jwtUtil.validateToken(token);

        assertTrue(isValid);
    }

    @Test
    void validateToken_ShouldReturnFalse_ForInvalidToken() {
        boolean isValid = jwtUtil.validateToken("invalid-token");
        assertFalse(isValid);
    }

    @Test
    void isTokenExpired_ShouldReturnFalse_ForFreshToken() {
        UUID userId = UUID.randomUUID();
        String role = "USER";

        String token = jwtUtil.generateAccessToken(userId, role);
        boolean isExpired = jwtUtil.isTokenExpired(token);

        assertFalse(isExpired);
    }

    @Test
    void getPublicKeyPem_ShouldReturnValidPem() {
        String publicKeyPem = jwtUtil.getPublicKeyPem();

        assertNotNull(publicKeyPem);
        assertFalse(publicKeyPem.isEmpty());
        assertTrue(publicKeyPem.contains("-----BEGIN PUBLIC KEY-----"));
        assertTrue(publicKeyPem.contains("-----END PUBLIC KEY-----"));
    }

    @Test
    void keyPersistence_ShouldLoadSameKeysAfterRestart() {
        UUID userId = UUID.randomUUID();
        String token1 = jwtUtil.generateAccessToken(userId, "USER");
        String publicKeyPem1 = jwtUtil.getPublicKeyPem();

        String token2 = jwtUtil.generateAccessToken(userId, "USER");
        String publicKeyPem2 = jwtUtil.getPublicKeyPem();

        assertEquals(publicKeyPem1, publicKeyPem2);

        assertNotEquals(token1, token2);

        assertTrue(jwtUtil.validateToken(token1));
        assertTrue(jwtUtil.validateToken(token2));
    }
}