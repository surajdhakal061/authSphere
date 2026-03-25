package com.suraj.authsphere.auth.repository;

import com.suraj.authsphere.auth.domain.EmailVerificationToken;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, UUID> {

    Optional<EmailVerificationToken> findByTokenHashAndExpiresAtAfter(String tokenHash, Instant now);

    Optional<EmailVerificationToken> findByUserIdAndVerifiedAtIsNull(UUID userId);

    Optional<EmailVerificationToken> findByEmailAndVerifiedAtIsNull(String email);

    int deleteByExpiresAtBefore(Instant now);
}

