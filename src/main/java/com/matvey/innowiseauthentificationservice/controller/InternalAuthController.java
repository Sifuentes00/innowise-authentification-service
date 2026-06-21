package com.matvey.innowiseauthentificationservice.controller;

import com.matvey.innowiseauthentificationservice.dto.AdminRegisterRequest;
import com.matvey.innowiseauthentificationservice.dto.RegisterRequest;
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
@RequestMapping("/internal")
@RequiredArgsConstructor
@Tag(name = "Internal", description = "Internal endpoints for Gateway")
public class InternalAuthController {

    private final AuthService authService;

    @PostMapping("/credentials/{userId}")
    @Operation(summary = "Create user credentials (internal for Gateway)")
    public ResponseEntity<Void> createCredentialsInternal(
            @PathVariable UUID userId,
            @Valid @RequestBody RegisterRequest registerRequest) {
        authService.createCredentials(registerRequest, userId);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/admin-credentials/{userId}")
    @Operation(summary = "Create admin credentials (internal for Gateway)")
    public ResponseEntity<Void> createAdminCredentialsInternal(
            @PathVariable UUID userId,
            @Valid @RequestBody AdminRegisterRequest adminRegisterRequest) {
        authService.createAdminCredentials(adminRegisterRequest, userId);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @DeleteMapping("/credentials/{userId}")
    @Operation(summary = "Delete credentials (internal for Gateway rollback)")
    public ResponseEntity<Void> deleteCredentialsInternal(@PathVariable UUID userId) {
        authService.deleteByUserId(userId);
        return ResponseEntity.noContent().build();
    }
}
