package com.matvey.innowiseauthentificationservice.repository;

import com.matvey.innowiseauthentificationservice.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByToken(String token);
    Optional<RefreshToken> findByTokenHash(String tokenHash);
    List<RefreshToken> findByUserId(UUID userId);
    void deleteByToken(String token);
    void deleteByUserId(UUID userId);
}
