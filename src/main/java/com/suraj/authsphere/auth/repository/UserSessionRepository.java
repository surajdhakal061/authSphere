package com.suraj.authsphere.auth.repository;

import com.suraj.authsphere.auth.domain.UserSession;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {

    Optional<UserSession> findByRefreshTokenJti(String refreshTokenJti);

    List<UserSession> findByUserIdAndRevokedAtIsNull(UUID userId);

    List<UserSession> findByUserIdAndRevokedAtIsNullAndExpiresAtAfter(UUID userId, Instant now);
}

