package com.matvey.innowiseauthentificationservice.repository;

import com.matvey.innowiseauthentificationservice.entity.UserCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserCredentialRepository extends JpaRepository<UserCredential, UUID> {
    Optional<UserCredential> findByEmail(String email);
    Optional<UserCredential> findByUserId(UUID userId);
    boolean existsByEmail(String email);

    @Modifying
    @Query("DELETE FROM UserCredential u WHERE u.userId = :userId")
    void deleteByUserId(@Param("userId") UUID userId);
}
