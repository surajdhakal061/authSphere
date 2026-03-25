package com.suraj.authsphere.auth.repository;

import com.suraj.authsphere.auth.domain.BiometricCredential;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BiometricCredentialRepository extends JpaRepository<BiometricCredential, UUID> {

    Optional<BiometricCredential> findByCredentialId(String credentialId);

    List<BiometricCredential> findByUserIdAndRevokedAtIsNull(UUID userId);

    boolean existsByCredentialId(String credentialId);
}

