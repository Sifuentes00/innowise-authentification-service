package com.matvey.innowiseauthentificationservice.util;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class JwtUtilTest {

    @Autowired
    private JwtUtil jwtUtil;

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
}