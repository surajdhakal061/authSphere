package com.suraj.authsphere.auth.service;

import com.suraj.authsphere.auth.config.JwtProperties;
import com.suraj.authsphere.auth.domain.UserAccount;
import com.suraj.authsphere.auth.domain.UserSession;
import com.suraj.authsphere.auth.domain.UserStatus;
import com.suraj.authsphere.auth.dto.ApiMessageResponse;
import com.suraj.authsphere.auth.dto.LoginRequest;
import com.suraj.authsphere.auth.dto.RefreshTokenRequest;
import com.suraj.authsphere.auth.dto.RegisterRequest;
import com.suraj.authsphere.auth.dto.TokenPairResponse;
import com.suraj.authsphere.auth.repository.UserAccountRepository;
import com.suraj.authsphere.auth.repository.UserSessionRepository;
import com.suraj.authsphere.auth.security.JwtTokenService;
import com.suraj.authsphere.auth.security.JwtTokenService.RefreshTokenClaims;
import com.suraj.authsphere.common.exception.AccountLockedException;
import com.suraj.authsphere.common.exception.BadRequestException;
import com.suraj.authsphere.common.exception.UnauthorizedException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Locale;
import java.util.UUID;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;

    private final UserAccountRepository userAccountRepository;
    private final UserSessionRepository userSessionRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;
    private final JwtProperties jwtProperties;

    public AuthService(
        UserAccountRepository userAccountRepository,
        UserSessionRepository userSessionRepository,
        PasswordEncoder passwordEncoder,
        JwtTokenService jwtTokenService,
        JwtProperties jwtProperties
    ) {
        this.userAccountRepository = userAccountRepository;
        this.userSessionRepository = userSessionRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenService = jwtTokenService;
        this.jwtProperties = jwtProperties;
    }

    @Transactional
    public TokenPairResponse register(RegisterRequest request) {
        String normalizedEmail = normalizeEmail(request.email());
        if (userAccountRepository.existsByEmailIgnoreCase(normalizedEmail)) {
            throw new BadRequestException("Email already registered");
        }

        UserAccount user = new UserAccount();
        user.setId(UUID.randomUUID());
        user.setEmail(normalizedEmail);
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setStatus(UserStatus.PENDING_VERIFICATION);
        user.setEmailVerified(false);
        user.setFailedLoginCount(0);
        user.setTokenVersion(1);

        userAccountRepository.save(user);
        return generateTokenPair(user);
    }

    @Transactional
    public TokenPairResponse login(LoginRequest request) {
        UserAccount user = userAccountRepository
            .findByEmailIgnoreCase(normalizeEmail(request.email()))
            .orElseThrow(() -> new UnauthorizedException("Invalid email or password"));

        validateAccountState(user);

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            registerFailedAttempt(user);
            throw new UnauthorizedException("Invalid email or password");
        }

        user.setFailedLoginCount(0);
        user.setLockedUntil(null);
        userAccountRepository.save(user);

        return generateTokenPair(user);
    }

    @Transactional
    public TokenPairResponse refresh(RefreshTokenRequest request) {
        RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(request.refreshToken());

        UserAccount user = userAccountRepository
            .findById(claims.userId())
            .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));

        if (!claims.tokenVersion().equals(user.getTokenVersion())) {
            throw new UnauthorizedException("Refresh token is no longer valid");
        }

        UserSession activeSession = userSessionRepository
            .findByRefreshTokenJti(claims.jti())
            .orElseThrow(() -> new UnauthorizedException("Refresh session not found"));

        if (activeSession.getRevokedAt() != null || activeSession.getExpiresAt().isBefore(Instant.now())) {
            throw new UnauthorizedException("Refresh token is no longer valid");
        }

        if (!hashToken(request.refreshToken()).equals(activeSession.getRefreshTokenHash())) {
            throw new UnauthorizedException("Refresh token is no longer valid");
        }

        activeSession.setRevokedAt(Instant.now());
        activeSession.setRevokeReason("ROTATED");
        userSessionRepository.save(activeSession);

        return generateTokenPair(user);
    }

    @Transactional
    public ApiMessageResponse logout(RefreshTokenRequest request) {
        RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(request.refreshToken());
        userSessionRepository
            .findByRefreshTokenJti(claims.jti())
            .ifPresent(session -> {
                session.setRevokedAt(Instant.now());
                session.setRevokeReason("LOGOUT");
                userSessionRepository.save(session);
            });
        return new ApiMessageResponse("Logged out successfully");
    }

    @Transactional
    public ApiMessageResponse logoutAll(RefreshTokenRequest request) {
        RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(request.refreshToken());

        UserAccount user = userAccountRepository
            .findById(claims.userId())
            .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));

        user.setTokenVersion(user.getTokenVersion() + 1);
        userAccountRepository.save(user);

        for (UserSession session : userSessionRepository.findByUserIdAndRevokedAtIsNull(user.getId())) {
            session.setRevokedAt(Instant.now());
            session.setRevokeReason("LOGOUT_ALL");
            userSessionRepository.save(session);
        }

        return new ApiMessageResponse("Logged out from all devices");
    }

    private void validateAccountState(UserAccount user) {
        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now())) {
            throw new AccountLockedException("Account temporarily locked due to failed login attempts");
        }

        if (user.getStatus() == UserStatus.DISABLED) {
            throw new UnauthorizedException("Account is disabled");
        }
    }

    private void registerFailedAttempt(UserAccount user) {
        int nextAttempts = user.getFailedLoginCount() + 1;
        user.setFailedLoginCount(nextAttempts);

        if (nextAttempts >= MAX_FAILED_ATTEMPTS) {
            user.setStatus(UserStatus.LOCKED);
            user.setLockedUntil(Instant.now().plus(15, ChronoUnit.MINUTES));
            user.setFailedLoginCount(0);
        }

        userAccountRepository.save(user);
    }

    private TokenPairResponse generateTokenPair(UserAccount user) {
        String accessToken = jwtTokenService.generateAccessToken(user);
        String refreshToken = jwtTokenService.generateRefreshToken(user);
        persistSession(user.getId(), refreshToken);

        return new TokenPairResponse(
            accessToken,
            refreshToken,
            jwtProperties.accessTokenTtlSeconds(),
            jwtProperties.refreshTokenTtlSeconds()
        );
    }

    private void persistSession(UUID userId, String refreshToken) {
        RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(refreshToken);

        UserSession session = new UserSession();
        session.setId(UUID.randomUUID());
        session.setUserId(userId);
        session.setRefreshTokenJti(claims.jti());
        session.setRefreshTokenHash(hashToken(refreshToken));
        session.setIssuedAt(Instant.now());
        session.setExpiresAt(claims.expiresAt());

        userSessionRepository.save(session);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }
}

