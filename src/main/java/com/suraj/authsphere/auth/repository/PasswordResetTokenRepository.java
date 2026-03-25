package com.suraj.authsphere.auth.repository;

import com.suraj.authsphere.auth.domain.PasswordResetToken;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    Optional<PasswordResetToken> findByTokenHashAndExpiresAtAfter(String tokenHash, Instant now);

    Optional<PasswordResetToken> findByUserIdAndUsedAtIsNull(UUID userId);

    int deleteByExpiresAtBefore(Instant now);
}

