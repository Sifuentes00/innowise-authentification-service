package com.matvey.innowiseauthentificationservice.service;

import com.matvey.innowiseauthentificationservice.dto.AuthResponse;
import com.matvey.innowiseauthentificationservice.dto.LoginRequest;
import com.matvey.innowiseauthentificationservice.dto.RefreshRequest;
import com.matvey.innowiseauthentificationservice.dto.RegisterRequest;
import com.matvey.innowiseauthentificationservice.dto.ValidateRequest;
import com.matvey.innowiseauthentificationservice.dto.ValidateResponse;
import com.matvey.innowiseauthentificationservice.entity.RefreshToken;
import com.matvey.innowiseauthentificationservice.entity.UserCredential;
import com.matvey.innowiseauthentificationservice.mapper.UserCredentialMapper;
import com.matvey.innowiseauthentificationservice.repository.RefreshTokenRepository;
import com.matvey.innowiseauthentificationservice.repository.UserCredentialRepository;
import com.matvey.innowiseauthentificationservice.exception.EmailAlreadyExistsException;
import com.matvey.innowiseauthentificationservice.exception.InvalidCredentialsException;
import com.matvey.innowiseauthentificationservice.exception.InvalidRefreshTokenException;
import com.matvey.innowiseauthentificationservice.exception.RefreshTokenExpiredException;
import com.matvey.innowiseauthentificationservice.exception.UserNotFoundException;
import com.matvey.innowiseauthentificationservice.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserCredentialRepository userCredentialRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserCredentialMapper userCredentialMapper;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void register(RegisterRequest registerRequest, UUID userId) {
        if (userCredentialRepository.existsByEmail(registerRequest.getEmail())) {
            throw new EmailAlreadyExistsException("Email already exists: " + registerRequest.getEmail());
        }

        UserCredential userCredential = userCredentialMapper.toEntity(registerRequest, userId);
        userCredential.setPasswordHash(passwordEncoder.encode(registerRequest.getPassword()));
        userCredentialRepository.save(userCredential);
    }

    public AuthResponse login(LoginRequest loginRequest) {
        UserCredential userCredential = userCredentialRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

        if (!passwordEncoder.matches(loginRequest.getPassword(), userCredential.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        String accessToken = jwtUtil.generateAccessToken(userCredential.getUserId(), userCredential.getRole().name());
        String refreshToken = jwtUtil.generateRefreshToken(userCredential.getUserId());

        saveRefreshToken(userCredential.getUserId(), refreshToken);

        return new AuthResponse(accessToken, refreshToken);
    }

    public ValidateResponse validate(ValidateRequest validateRequest) {
        if (!jwtUtil.validateToken(validateRequest.getToken())) {
            return new ValidateResponse(false, null, null);
        }

        UUID userId = jwtUtil.extractUserId(validateRequest.getToken());
        String role = jwtUtil.extractRole(validateRequest.getToken());

        return new ValidateResponse(true, userId.toString(), role);
    }

    @Transactional
    public AuthResponse refresh(RefreshRequest refreshRequest) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshRequest.getRefreshToken())
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        if (refreshToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new RefreshTokenExpiredException("Refresh token expired");
        }

        UserCredential userCredential = userCredentialRepository.findByUserId(refreshToken.getUserId())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        String newAccessToken = jwtUtil.generateAccessToken(userCredential.getUserId(), userCredential.getRole().name());
        String newRefreshToken = jwtUtil.generateRefreshToken(userCredential.getUserId());

        refreshTokenRepository.delete(refreshToken);
        saveRefreshToken(userCredential.getUserId(), newRefreshToken);

        return new AuthResponse(newAccessToken, newRefreshToken);
    }

    private void saveRefreshToken(UUID userId, String token) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUserId(userId);
        refreshToken.setToken(token);
        refreshToken.setExpiryDate(LocalDateTime.now().plusDays(7));
        refreshToken.setCreatedAt(LocalDateTime.now());
        refreshTokenRepository.save(refreshToken);
    }
}
