package com.suraj.authsphere.auth.repository;

import com.suraj.authsphere.auth.domain.BiometricChallenge;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BiometricChallengeRepository extends JpaRepository<BiometricChallenge, UUID> {

    Optional<BiometricChallenge> findByIdAndUserId(UUID id, UUID userId);

    int deleteByExpiresAtBefore(Instant now);
}

