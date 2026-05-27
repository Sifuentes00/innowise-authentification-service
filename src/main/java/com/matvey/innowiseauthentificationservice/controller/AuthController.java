package com.matvey.innowiseauthentificationservice.controller;

import com.matvey.innowiseauthentificationservice.dto.AuthResponse;
import com.matvey.innowiseauthentificationservice.dto.LoginRequest;
import com.matvey.innowiseauthentificationservice.dto.RefreshRequest;
import com.matvey.innowiseauthentificationservice.dto.RegisterRequest;
import com.matvey.innowiseauthentificationservice.dto.ValidateRequest;
import com.matvey.innowiseauthentificationservice.dto.ValidateResponse;
import com.matvey.innowiseauthentificationservice.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication endpoints")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register/{userId}")
    @Operation(summary = "Register user credentials")
    public ResponseEntity<Void> register(
            @PathVariable UUID userId,
            @Valid @RequestBody RegisterRequest registerRequest) {
        authService.register(registerRequest, userId);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/login")
    @Operation(summary = "Login and get JWT tokens")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        AuthResponse authResponse = authService.login(loginRequest);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/validate")
    @Operation(summary = "Validate JWT token")
    public ResponseEntity<ValidateResponse> validate(@Valid @RequestBody ValidateRequest validateRequest) {
        ValidateResponse validateResponse = authService.validate(validateRequest);
        return ResponseEntity.ok(validateResponse);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh JWT token")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest refreshRequest) {
        AuthResponse authResponse = authService.refresh(refreshRequest);
        return ResponseEntity.ok(authResponse);
    }
}
