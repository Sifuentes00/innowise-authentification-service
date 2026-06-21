package com.matvey.innowiseauthentificationservice.controller;

import com.matvey.innowiseauthentificationservice.dto.AuthResponse;
import com.matvey.innowiseauthentificationservice.dto.LoginRequest;
import com.matvey.innowiseauthentificationservice.dto.PublicKeyResponse;
import com.matvey.innowiseauthentificationservice.dto.RefreshRequest;
import com.matvey.innowiseauthentificationservice.service.AuthService;
import com.matvey.innowiseauthentificationservice.util.JwtUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication endpoints")
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;

    @PostMapping("/login")
    @Operation(summary = "Login and get JWT tokens")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        AuthResponse authResponse = authService.login(loginRequest);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh JWT token")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest refreshRequest) {
        AuthResponse authResponse = authService.refresh(refreshRequest);
        return ResponseEntity.ok(authResponse);
    }

    @GetMapping("/public-key")
    @Operation(summary = "Get public key for JWT validation")
    public ResponseEntity<PublicKeyResponse> getPublicKey() {
        String publicKeyPem = jwtUtil.getPublicKeyPem();
        PublicKeyResponse response = PublicKeyResponse.builder()
                .publicKey(publicKeyPem)
                .algorithm("RS256")
                .build();
        return ResponseEntity.ok(response);
    }
}
