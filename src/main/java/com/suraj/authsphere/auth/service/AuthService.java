package com.suraj.authsphere.auth.service;

import com.suraj.authsphere.auth.config.JwtProperties;
import com.suraj.authsphere.auth.config.AuthRateLimitProperties;
import com.suraj.authsphere.auth.domain.EmailVerificationToken;
import com.suraj.authsphere.auth.domain.PasswordResetToken;
import com.suraj.authsphere.auth.domain.UserAccount;
import com.suraj.authsphere.auth.domain.UserSession;
import com.suraj.authsphere.auth.domain.UserStatus;
import com.suraj.authsphere.auth.dto.ApiMessageResponse;
import com.suraj.authsphere.auth.dto.LoginRequest;
import com.suraj.authsphere.auth.dto.RefreshTokenRequest;
import com.suraj.authsphere.auth.dto.RevokeSessionRequest;
import com.suraj.authsphere.auth.dto.RegisterRequest;
import com.suraj.authsphere.auth.dto.SessionSummaryResponse;
import com.suraj.authsphere.auth.dto.TokenPairResponse;
import com.suraj.authsphere.auth.repository.EmailVerificationTokenRepository;
import com.suraj.authsphere.auth.repository.PasswordResetTokenRepository;
import com.suraj.authsphere.auth.repository.UserAccountRepository;
import com.suraj.authsphere.auth.repository.UserSessionRepository;
import com.suraj.authsphere.auth.security.JwtTokenService;
import com.suraj.authsphere.auth.security.JwtTokenService.RefreshTokenClaims;
import com.suraj.authsphere.common.exception.AccountLockedException;
import com.suraj.authsphere.common.exception.BadRequestException;
import com.suraj.authsphere.common.exception.TooManyRequestsException;
import com.suraj.authsphere.common.exception.UnauthorizedException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final UserAccountRepository userAccountRepository;
    private final UserSessionRepository userSessionRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;
    private final JwtProperties jwtProperties;
    private final AuthRateLimiter authRateLimiter;
    private final AuthRateLimitProperties authRateLimitProperties;

    public AuthService(
            UserAccountRepository userAccountRepository,
            UserSessionRepository userSessionRepository,
            PasswordResetTokenRepository passwordResetTokenRepository,
            EmailVerificationTokenRepository emailVerificationTokenRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenService jwtTokenService,
            JwtProperties jwtProperties,
            AuthRateLimiter authRateLimiter,
            AuthRateLimitProperties authRateLimitProperties
    ) {
        this.userAccountRepository = userAccountRepository;
        this.userSessionRepository = userSessionRepository;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.emailVerificationTokenRepository = emailVerificationTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenService = jwtTokenService;
        this.jwtProperties = jwtProperties;
        this.authRateLimiter = authRateLimiter;
        this.authRateLimitProperties = authRateLimitProperties;
    }

    @Transactional
    public TokenPairResponse register(RegisterRequest request) {
        return register(request, ClientContext.unknown());
    }

    @Transactional
    public TokenPairResponse register(RegisterRequest request, ClientContext clientContext) {
        String normalizedEmail = normalizeEmail(request.email());
        if(userAccountRepository.existsByEmailIgnoreCase(normalizedEmail)) {
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
        return generateTokenPair(user, clientContext);
    }

    @Transactional
    public TokenPairResponse login(LoginRequest request) {
        return login(request, ClientContext.unknown());
    }

    @Transactional
    public TokenPairResponse login(LoginRequest request, ClientContext clientContext) {
        assertRateLimit("login", clientContext.ipAddress(), authRateLimitProperties.loginMaxPerMinute());

        UserAccount user = userAccountRepository
                .findByEmailIgnoreCase(normalizeEmail(request.email()))
                .orElseThrow(() -> new UnauthorizedException("Invalid email or password"));

        validateAccountState(user);

        if(!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            registerFailedAttempt(user);
            throw new UnauthorizedException("Invalid email or password");
        }

        user.setFailedLoginCount(0);
        user.setLockedUntil(null);
        userAccountRepository.save(user);

        return generateTokenPair(user, clientContext);
    }

    @Transactional
    public TokenPairResponse refresh(RefreshTokenRequest request) {
        return refresh(request, ClientContext.unknown());
    }

    @Transactional
    public TokenPairResponse refresh(RefreshTokenRequest request, ClientContext clientContext) {
        assertRateLimit("refresh", clientContext.ipAddress(), authRateLimitProperties.refreshMaxPerMinute());

        RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(request.refreshToken());
        UserAccount user = resolveRefreshUser(claims);

        UserSession activeSession = userSessionRepository
                .findByRefreshTokenJti(claims.jti())
                .orElseThrow(() -> new UnauthorizedException("Refresh session not found"));

        if(activeSession.getRevokedAt() != null || activeSession.getExpiresAt().isBefore(Instant.now())) {
            throw new UnauthorizedException("Refresh token is no longer valid");
        }

        if(!hashToken(request.refreshToken()).equals(activeSession.getRefreshTokenHash())) {
            throw new UnauthorizedException("Refresh token is no longer valid");
        }

        activeSession.setRevokedAt(Instant.now());
        activeSession.setRevokeReason("ROTATED");
        activeSession.setLastSeenAt(Instant.now());
        userSessionRepository.save(activeSession);

        return generateTokenPair(user, clientContext);
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
        UserAccount user = resolveRefreshUser(claims);

        user.setTokenVersion(user.getTokenVersion() + 1);
        userAccountRepository.save(user);

        for(UserSession session : userSessionRepository.findByUserIdAndRevokedAtIsNull(user.getId())) {
            session.setRevokedAt(Instant.now());
            session.setRevokeReason("LOGOUT_ALL");
            userSessionRepository.save(session);
        }

        return new ApiMessageResponse("Logged out from all devices");
    }

    @Transactional(readOnly = true)
    public List<SessionSummaryResponse> listActiveSessions(RefreshTokenRequest request) {
        RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(request.refreshToken());
        UserAccount user = resolveRefreshUser(claims);

        return userSessionRepository
                .findByUserIdAndRevokedAtIsNullAndExpiresAtAfter(user.getId(), Instant.now())
                .stream()
                .map(session -> new SessionSummaryResponse(
                        session.getId(),
                        session.getDeviceName(),
                        session.getIpAddress(),
                        session.getUserAgent(),
                        session.getIssuedAt(),
                        session.getExpiresAt(),
                        claims.jti().equals(session.getRefreshTokenJti())
                ))
                .toList();
    }

    @Transactional
    public ApiMessageResponse revokeSession(RevokeSessionRequest request) {
        RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(request.refreshToken());
        UserAccount user = resolveRefreshUser(claims);

        UserSession session = userSessionRepository
                .findByIdAndUserId(request.sessionId(), user.getId())
                .orElseThrow(() -> new BadRequestException("Session not found"));

        if(session.getRevokedAt() != null || session.getExpiresAt().isBefore(Instant.now())) {
            return new ApiMessageResponse("Session is already inactive");
        }

        session.setRevokedAt(Instant.now());
        session.setRevokeReason("MANUAL_REVOKE");
        session.setLastSeenAt(Instant.now());
        userSessionRepository.save(session);
        return new ApiMessageResponse("Session revoked successfully");
    }

    @Transactional
    public ApiMessageResponse revokeSession(String refreshToken, UUID sessionId) {
        return revokeSession(new RevokeSessionRequest(refreshToken, sessionId));
    }

    /**
     * Initiate password reset flow by sending reset token
     */
    @Transactional
    public ApiMessageResponse initiatePasswordReset(String email) {
        String normalizedEmail = normalizeEmail(email);
        UserAccount user = userAccountRepository
                .findByEmailIgnoreCase(normalizedEmail)
                .orElseThrow(() -> new BadRequestException("No account found with this email"));

        // In a real system, this would send an email with the reset link
        // For now, we'll just generate and store the token
        String resetToken = generateSecureToken();
        String tokenHash = hashToken(resetToken);

        // Store in database for audit trail
        PasswordResetToken resetTokenEntity = new PasswordResetToken();
        resetTokenEntity.setId(java.util.UUID.randomUUID());
        resetTokenEntity.setUserId(user.getId());
        resetTokenEntity.setTokenHash(tokenHash);
        resetTokenEntity.setExpiresAt(Instant.now().plusSeconds(3600)); // 1 hour
        passwordResetTokenRepository.save(resetTokenEntity);

        // TODO: Send The Token Through Email for Verification
        return new ApiMessageResponse("Password reset link sent to email");
    }

    /**
     * Reset password using reset token
     */
    @Transactional
    public ApiMessageResponse resetPassword(String resetToken, String newPassword) {
        String tokenHash = hashToken(resetToken);

        PasswordResetToken tokenEntity = passwordResetTokenRepository
                .findByTokenHashAndExpiresAtAfter(tokenHash, Instant.now())
                .orElseThrow(() -> new BadRequestException("Invalid or expired reset token"));

        if(tokenEntity.getUsedAt() != null) {
            throw new BadRequestException("Reset token has already been used");
        }

        UserAccount user = userAccountRepository
                .findById(tokenEntity.getUserId())
                .orElseThrow(() -> new UnauthorizedException("User not found"));

        // Update password and increment token version to invalidate all refresh tokens
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setTokenVersion(user.getTokenVersion() + 1);
        user.setFailedLoginCount(0);
        user.setLockedUntil(null);
        userAccountRepository.save(user);

        // Mark token as used
        tokenEntity.setUsedAt(Instant.now());
        passwordResetTokenRepository.save(tokenEntity);

        // Revoke all active sessions (force logout)
        for(UserSession session : userSessionRepository.findByUserIdAndRevokedAtIsNull(user.getId())) {
            session.setRevokedAt(Instant.now());
            session.setRevokeReason("PASSWORD_RESET");
            userSessionRepository.save(session);
        }

        return new ApiMessageResponse("Password has been reset successfully");
    }

    /**
     * Resend email verification token
     */
    @Transactional
    public ApiMessageResponse resendEmailVerification(String email) {
        String normalizedEmail = normalizeEmail(email);
        UserAccount user = userAccountRepository
                .findByEmailIgnoreCase(normalizedEmail)
                .orElseThrow(() -> new BadRequestException("No account found with this email"));

        if(user.isEmailVerified()) {
            return new ApiMessageResponse("Email is already verified");
        }

        String verificationToken = generateSecureToken();
        String tokenHash = hashToken(verificationToken);

        // Delete existing tokens for this user
        emailVerificationTokenRepository
                .findByUserIdAndVerifiedAtIsNull(user.getId())
                .ifPresent(existingToken -> emailVerificationTokenRepository.delete(existingToken));

        // Create new verification token
        EmailVerificationToken tokenEntity = new EmailVerificationToken();
        tokenEntity.setId(java.util.UUID.randomUUID());
        tokenEntity.setUserId(user.getId());
        tokenEntity.setEmail(user.getEmail());
        tokenEntity.setTokenHash(tokenHash);
        tokenEntity.setExpiresAt(Instant.now().plusSeconds(86400)); // 24 hours
        emailVerificationTokenRepository.save(tokenEntity);

        // TODO: Send email with verification link containing the plain token
        return new ApiMessageResponse("Verification email sent");
    }

    /**
     * Verify email using verification token
     */
    @Transactional
    public ApiMessageResponse verifyEmail(String verificationToken) {
        String tokenHash = hashToken(verificationToken);

        EmailVerificationToken tokenEntity = emailVerificationTokenRepository
                .findByTokenHashAndExpiresAtAfter(tokenHash, Instant.now())
                .orElseThrow(() -> new BadRequestException("Invalid or expired verification token"));

        if(tokenEntity.getVerifiedAt() != null) {
            return new ApiMessageResponse("Email has already been verified");
        }

        UserAccount user = userAccountRepository
                .findById(tokenEntity.getUserId())
                .orElseThrow(() -> new UnauthorizedException("User not found"));

        // Mark email as verified and activate user
        user.setEmailVerified(true);
        if(user.getStatus() == UserStatus.PENDING_VERIFICATION) {
            user.setStatus(UserStatus.ACTIVE);
        }
        userAccountRepository.save(user);

        // Mark token as verified
        tokenEntity.setVerifiedAt(Instant.now());
        emailVerificationTokenRepository.save(tokenEntity);

        return new ApiMessageResponse("Email verified successfully");
    }

    private void validateAccountState(UserAccount user) {
        if(user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now())) {
            throw new AccountLockedException("Account temporarily locked due to failed login attempts");
        }

        if(user.getStatus() == UserStatus.DISABLED) {
            throw new UnauthorizedException("Account is disabled");
        }
    }

    private void registerFailedAttempt(UserAccount user) {
        int nextAttempts = user.getFailedLoginCount() + 1;
        user.setFailedLoginCount(nextAttempts);

        if(nextAttempts >= MAX_FAILED_ATTEMPTS) {
            user.setStatus(UserStatus.LOCKED);
            user.setLockedUntil(Instant.now().plus(15, ChronoUnit.MINUTES));
            user.setFailedLoginCount(0);
        }

        userAccountRepository.save(user);
    }

    private TokenPairResponse generateTokenPair(UserAccount user, ClientContext clientContext) {
        String accessToken = jwtTokenService.generateAccessToken(user);
        String refreshToken = jwtTokenService.generateRefreshToken(user);
        persistSession(user.getId(), refreshToken, clientContext);

        return new TokenPairResponse(
            accessToken,
            refreshToken,
            jwtProperties.accessTokenTtlSeconds(),
            jwtProperties.refreshTokenTtlSeconds()
        );
    }

    private void persistSession(UUID userId, String refreshToken, ClientContext clientContext) {
        RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(refreshToken);

        Instant now = Instant.now();
        UserSession session = new UserSession();
        session.setId(UUID.randomUUID());
        session.setUserId(userId);
        session.setRefreshTokenJti(claims.jti());
        session.setRefreshTokenHash(hashToken(refreshToken));
        session.setDeviceName(sanitize(clientContext.deviceName(), 120, "unknown-device"));
        session.setIpAddress(sanitize(clientContext.ipAddress(), 64, "unknown"));
        session.setUserAgent(sanitize(clientContext.userAgent(), 255, "unknown"));
        session.setIssuedAt(now);
        session.setExpiresAt(claims.expiresAt());
        session.setLastSeenAt(now);

        userSessionRepository.save(session);
    }

    private UserAccount resolveRefreshUser(RefreshTokenClaims claims) {
        UserAccount user = userAccountRepository
                .findById(claims.userId())
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));

        if(!claims.tokenVersion().equals(user.getTokenVersion())) {
            throw new UnauthorizedException("Refresh token is no longer valid");
        }
        return user;
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        }
        catch(NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    private String sanitize(String value, int maxLength, String fallback) {
        if(value == null || value.isBlank()) {
            return fallback;
        }
        return value.length() > maxLength ? value.substring(0, maxLength) : value;
    }

    private void assertRateLimit(String scope, String key, int limitPerMinute) {
        if(!authRateLimiter.allow(scope, key, limitPerMinute)) {
            throw new TooManyRequestsException("Too many requests. Please try again later.");
        }
    }

    /**
     * Generate a secure random token for password reset and email verification
     */
    private String generateSecureToken() {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}
