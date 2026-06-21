package com.matvey.innowiseauthentificationservice.service;

import com.matvey.innowiseauthentificationservice.dto.AdminRegisterRequest;
import com.matvey.innowiseauthentificationservice.dto.AuthResponse;
import com.matvey.innowiseauthentificationservice.dto.LoginRequest;
import com.matvey.innowiseauthentificationservice.dto.RefreshRequest;
import com.matvey.innowiseauthentificationservice.dto.RegisterRequest;
import com.matvey.innowiseauthentificationservice.entity.RefreshToken;
import com.matvey.innowiseauthentificationservice.entity.UserCredential;
import com.matvey.innowiseauthentificationservice.enums.RoleType;
import com.matvey.innowiseauthentificationservice.exception.EmailAlreadyExistsException;
import com.matvey.innowiseauthentificationservice.exception.InvalidCredentialsException;
import com.matvey.innowiseauthentificationservice.exception.InvalidRefreshTokenException;
import com.matvey.innowiseauthentificationservice.exception.RefreshTokenExpiredException;
import com.matvey.innowiseauthentificationservice.exception.UserNotFoundException;
import com.matvey.innowiseauthentificationservice.mapper.UserCredentialMapper;
import com.matvey.innowiseauthentificationservice.repository.RefreshTokenRepository;
import com.matvey.innowiseauthentificationservice.repository.UserCredentialRepository;
import com.matvey.innowiseauthentificationservice.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
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
    public AuthResponse login(LoginRequest loginRequest) {
        UserCredential userCredential = userCredentialRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

        if (!passwordEncoder.matches(loginRequest.getPassword(), userCredential.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        refreshTokenRepository.deleteByUserId(userCredential.getUserId());

        String accessToken = jwtUtil.generateAccessToken(userCredential.getUserId(), userCredential.getRole().name());
        String refreshToken = jwtUtil.generateRefreshToken(userCredential.getUserId());

        saveRefreshToken(userCredential.getUserId(), refreshToken);

        return new AuthResponse(accessToken, refreshToken);
    }

    @Transactional
    public AuthResponse refresh(RefreshRequest refreshRequest) {
        String tokenHash = hashToken(refreshRequest.getRefreshToken());
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
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
        refreshToken.setTokenHash(hashToken(token));
        refreshToken.setExpiryDate(LocalDateTime.now().plusSeconds(jwtUtil.getRefreshTokenExpiration() / 1000));
        refreshToken.setCreatedAt(LocalDateTime.now());
        refreshTokenRepository.save(refreshToken);
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes());
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }

    @Transactional
    public void createCredentials(RegisterRequest request, UUID userId) {
        if (userCredentialRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Email already exists: " + request.getEmail());
        }
        UserCredential userCredential = userCredentialMapper.toEntity(request, userId);
        userCredential.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        userCredential.setRole(RoleType.USER);
        userCredentialRepository.save(userCredential);
    }

    @Transactional
    public void createAdminCredentials(AdminRegisterRequest request, UUID userId) {
        if (userCredentialRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Email already exists: " + request.getEmail());
        }
        UserCredential userCredential = new UserCredential();
        userCredential.setUserId(userId);
        userCredential.setEmail(request.getEmail());
        userCredential.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        userCredential.setRole(request.getRole());
        userCredentialRepository.save(userCredential);
    }

    @Transactional
    public void deleteByUserId(UUID userId) {
        userCredentialRepository.deleteByUserId(userId);
        refreshTokenRepository.deleteByUserId(userId);
    }
}
