package com.matvey.innowiseauthentificationservice.repository;

import com.matvey.innowiseauthentificationservice.entity.UserCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserCredentialRepository extends JpaRepository<UserCredential, UUID> {
    Optional<UserCredential> findByEmail(String email);
    Optional<UserCredential> findByUserId(UUID userId);
    boolean existsByEmail(String email);
}
