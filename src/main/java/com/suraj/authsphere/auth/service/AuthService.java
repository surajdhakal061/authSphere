package com.suraj.authsphere.auth.service;

import com.suraj.authsphere.auth.config.AuthRateLimitProperties;
import com.suraj.authsphere.auth.config.EmailVerificationTokenProperties;
import com.suraj.authsphere.auth.config.JwtProperties;
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
import com.suraj.authsphere.audit.domain.AuditEventType;
import com.suraj.authsphere.audit.domain.AuditOutcome;
import com.suraj.authsphere.audit.domain.AuditSeverity;
import com.suraj.authsphere.audit.service.AuditService;
import com.suraj.authsphere.common.exception.AccountLockedException;
import com.suraj.authsphere.common.exception.BadRequestException;
import com.suraj.authsphere.common.exception.TooManyRequestsException;
import com.suraj.authsphere.common.exception.UnauthorizedException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Logger LOG = LoggerFactory.getLogger(AuthService.class);

    private final UserAccountRepository userAccountRepository;
    private final UserSessionRepository userSessionRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;
    private final JwtProperties jwtProperties;
    private final EmailVerificationTokenProperties emailVerificationTokenProperties;
    private final VerificationEmailService verificationEmailService;
    private final ResetPasswordEmailService resetPasswordEmailService;
    private final AuthRateLimiter authRateLimiter;
    private final AuthRateLimitProperties authRateLimitProperties;
    private final FailedLoginAttemptService failedLoginAttemptService;
    private final AuditService auditService;

    public AuthService(
            UserAccountRepository userAccountRepository,
            UserSessionRepository userSessionRepository,
            PasswordResetTokenRepository passwordResetTokenRepository,
            EmailVerificationTokenRepository emailVerificationTokenRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenService jwtTokenService,
            JwtProperties jwtProperties,
            EmailVerificationTokenProperties emailVerificationTokenProperties,
            VerificationEmailService verificationEmailService,
            ResetPasswordEmailService resetPasswordEmailService,
            AuthRateLimiter authRateLimiter,
            AuthRateLimitProperties authRateLimitProperties,
            FailedLoginAttemptService failedLoginAttemptService,
            AuditService auditService
    ) {
        this.userAccountRepository = userAccountRepository;
        this.userSessionRepository = userSessionRepository;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.emailVerificationTokenRepository = emailVerificationTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenService = jwtTokenService;
        this.jwtProperties = jwtProperties;
        this.emailVerificationTokenProperties = emailVerificationTokenProperties;
        this.verificationEmailService = verificationEmailService;
        this.resetPasswordEmailService = resetPasswordEmailService;
        this.authRateLimiter = authRateLimiter;
        this.authRateLimitProperties = authRateLimitProperties;
        this.failedLoginAttemptService = failedLoginAttemptService;
        this.auditService = auditService;
    }

    @Transactional
    public ApiMessageResponse register(RegisterRequest request) {
        return register(request, ClientContext.unknown());
    }

    @Transactional
    public ApiMessageResponse register(RegisterRequest request, ClientContext clientContext) {
        String normalizedEmail = normalizeEmail(request.getEmail());
        LOG.info("Register attempt for email={} ip={}", normalizedEmail, clientContext.ipAddress());
        
        // Validate that password and confirmPassword match
        if(!request.getPassword().equals(request.getConfirmPassword())) {
            LOG.warn("Register failed due to password mismatch for email={}", normalizedEmail);
            auditService.recordSafely(auditService.build(
                AuditEventType.USER_REGISTRATION_FAILED,
                AuditOutcome.FAILURE,
                AuditSeverity.LOW,
                null,
                normalizedEmail,
                "user",
                normalizedEmail,
                "register",
                "auth",
                clientContext.ipAddress(),
                clientContext.userAgent(),
                "password_mismatch"
            ));
            throw new BadRequestException("Passwords do not match");
        }
        
        if(userAccountRepository.existsByEmailIgnoreCase(normalizedEmail)) {
            LOG.warn("Register failed because email already exists email={}", normalizedEmail);
            auditService.recordSafely(auditService.build(
                AuditEventType.USER_REGISTRATION_FAILED,
                AuditOutcome.FAILURE,
                AuditSeverity.LOW,
                null,
                normalizedEmail,
                "user",
                normalizedEmail,
                "register",
                "auth",
                clientContext.ipAddress(),
                clientContext.userAgent(),
                "email_exists"
            ));
            throw new BadRequestException("Email already registered. Please use a different email or login to your existing account.");
        }

        UserAccount user = new UserAccount();
        user.setId(UUID.randomUUID());
        user.setEmail(normalizedEmail);
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setStatus(UserStatus.PENDING_VERIFICATION);
        user.setEmailVerified(false);
        user.setFailedLoginCount(0);
        user.setTokenVersion(1);

        userAccountRepository.save(user);
        String verificationToken = issueEmailVerificationToken(user);
        verificationEmailService.sendVerificationEmail(user.getEmail(), verificationToken);
        LOG.info("User registered userId={} email={} status={}", user.getId(), normalizedEmail, user.getStatus());
        auditService.recordSafely(auditService.build(
            AuditEventType.USER_REGISTERED,
            AuditOutcome.SUCCESS,
            AuditSeverity.LOW,
            user.getId(),
            user.getEmail(),
            "user",
            user.getId().toString(),
            "register",
            "auth",
            clientContext.ipAddress(),
            clientContext.userAgent(),
            "pending_verification"
        ));
        auditService.recordSafely(auditService.build(
            AuditEventType.EMAIL_VERIFICATION_SENT,
            AuditOutcome.SUCCESS,
            AuditSeverity.LOW,
            user.getId(),
            user.getEmail(),
            "email_verification_token",
            user.getId().toString(),
            "send_verification",
            "auth",
            clientContext.ipAddress(),
            clientContext.userAgent(),
            null
        ));
        return new ApiMessageResponse("Registration successful. Please check your email to verify your account before logging in.");
    }

    @Transactional
    public TokenPairResponse login(LoginRequest request) {
        return login(request, ClientContext.unknown());
    }

    @Transactional
    public TokenPairResponse login(LoginRequest request, ClientContext clientContext) {
        assertRateLimit("login", clientContext.ipAddress(), authRateLimitProperties.loginMaxPerMinute());
        String normalizedEmail = normalizeEmail(request.getEmail());
        LOG.info("Login attempt email={} ip={}", normalizedEmail, clientContext.ipAddress());

        UserAccount user = userAccountRepository
                .findByEmailIgnoreCase(normalizedEmail)
                .orElse(null);

        if(user == null) {
            auditService.recordSafely(auditService.build(
                AuditEventType.USER_LOGIN_FAILED,
                AuditOutcome.FAILURE,
                AuditSeverity.MEDIUM,
                null,
                normalizedEmail,
                "user",
                normalizedEmail,
                "login",
                "auth",
                clientContext.ipAddress(),
                clientContext.userAgent(),
                "unknown_email"
            ));
            throw new UnauthorizedException("Invalid email or password");
        }

        validateAccountState(user);

        if(!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {   
            failedLoginAttemptService.registerFailedAttempt(user.getId());
            LOG.warn("Login failed due to invalid password userId={} email={}", user.getId(), normalizedEmail);
            auditService.recordSafely(auditService.build(
                AuditEventType.USER_LOGIN_FAILED,
                AuditOutcome.FAILURE,
                AuditSeverity.MEDIUM,
                user.getId(),
                user.getEmail(),
                "user",
                user.getId().toString(),
                "login",
                "auth",
                clientContext.ipAddress(),
                clientContext.userAgent(),
                "invalid_password"
            ));
            throw new UnauthorizedException("Invalid email or password");
        }

        user.setFailedLoginCount(0);
        user.setLockedUntil(null);
        userAccountRepository.save(user);
        LOG.info("Login successful userId={} email={}", user.getId(), normalizedEmail);
        auditService.recordSafely(auditService.build(
            AuditEventType.USER_LOGIN_SUCCEEDED,
            AuditOutcome.SUCCESS,
            AuditSeverity.LOW,
            user.getId(),
            user.getEmail(),
            "user",
            user.getId().toString(),
            "login",
            "auth",
            clientContext.ipAddress(),
            clientContext.userAgent(),
            null
        ));

        return generateTokenPair(user, clientContext);
    }

    @Transactional
    public TokenPairResponse refresh(RefreshTokenRequest request) {
        return refresh(request, ClientContext.unknown());
    }

    @Transactional
    public TokenPairResponse refresh(RefreshTokenRequest request, ClientContext clientContext) {
        assertRateLimit("refresh", clientContext.ipAddress(), authRateLimitProperties.refreshMaxPerMinute());
        LOG.info("Refresh token attempt ip={}", clientContext.ipAddress());
        Instant now = Instant.now();

        RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(request.getRefreshToken());
        UserAccount user = resolveRefreshUser(claims);

        validateAccountState(user);

        UserSession activeSession = userSessionRepository
                .findByRefreshTokenJti(claims.jti())
                .orElseThrow(() -> new UnauthorizedException("Refresh session not found"));

        if(activeSession.getRevokedAt() != null || activeSession.getExpiresAt().isBefore(now)) {
            LOG.warn("Refresh denied because session is inactive sessionId={} userId={}", activeSession.getId(), user.getId());
            throw new UnauthorizedException("Refresh token is no longer valid");
        }

        if(!activeSession.getUserId().equals(user.getId())){
            LOG.warn("Refresh denied because session does not belong to user sessionId={} userId={}", activeSession.getId(), user.getId());
            throw new UnauthorizedException("Refresh token is no longer valid");
        }

        if(!hashToken(request.getRefreshToken()).equals(activeSession.getRefreshTokenHash())) {
            LOG.warn("Refresh denied because refresh token hash mismatched sessionId={} userId={}", activeSession.getId(), user.getId());
            throw new UnauthorizedException("Refresh token is no longer valid");
        }

        activeSession.setRevokedAt(now);
        activeSession.setRevokeReason("ROTATED");
        activeSession.setLastSeenAt(now);
        userSessionRepository.save(activeSession);
        LOG.info("Refresh successful, old session rotated sessionId={} userId={}", activeSession.getId(), user.getId());
        auditService.recordSafely(auditService.build(
            AuditEventType.TOKEN_REFRESH_SUCCEEDED,
            AuditOutcome.SUCCESS,
            AuditSeverity.LOW,
            user.getId(),
            user.getEmail(),
            "session",
            activeSession.getId().toString(),
            "refresh",
            "auth",
            clientContext.ipAddress(),
            clientContext.userAgent(),
            "session_rotated"
        ));
        return generateTokenPair(user, clientContext);
    }

    @Transactional
    public ApiMessageResponse logout(RefreshTokenRequest request) {
        RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(request.getRefreshToken());
        LOG.info("Logout requested userId={}", claims.userId());
        UserAccount user = userAccountRepository.findById(claims.userId()).orElse(null);
        userSessionRepository
                .findByRefreshTokenJti(claims.jti())
                .ifPresent(session -> {
                    session.setRevokedAt(Instant.now());
                    session.setRevokeReason("LOGOUT");
                    userSessionRepository.save(session);
                });
        auditService.recordSafely(auditService.build(
            AuditEventType.USER_LOGOUT,
            AuditOutcome.SUCCESS,
            AuditSeverity.LOW,
            claims.userId(),
            user == null ? null : user.getEmail(),
            "session",
            claims.jti(),
            "logout",
            "auth",
            null,
            null,
            null
        ));
        return new ApiMessageResponse("Logged out successfully");
    }

    @Transactional
    public ApiMessageResponse logoutAll(RefreshTokenRequest request) {
        RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(request.getRefreshToken());
        UserAccount user = resolveRefreshUser(claims);
        LOG.info("Logout-all requested userId={} currentTokenVersion={}", user.getId(), user.getTokenVersion());

        user.setTokenVersion(user.getTokenVersion() + 1);
        userAccountRepository.save(user);

        for(UserSession session : userSessionRepository.findByUserIdAndRevokedAtIsNull(user.getId())) {
            session.setRevokedAt(Instant.now());
            session.setRevokeReason("LOGOUT_ALL");
            userSessionRepository.save(session);
        }
        LOG.info("Logout-all completed userId={} newTokenVersion={}", user.getId(), user.getTokenVersion());
        auditService.recordSafely(auditService.build(
            AuditEventType.USER_LOGOUT_ALL,
            AuditOutcome.SUCCESS,
            AuditSeverity.MEDIUM,
            user.getId(),
            user.getEmail(),
            "user",
            user.getId().toString(),
            "logout_all",
            "auth",
            null,
            null,
            null
        ));

        return new ApiMessageResponse("Logged out from all devices");
    }

    @Transactional(readOnly = true)
    public List<SessionSummaryResponse> listActiveSessions(RefreshTokenRequest request) {
        RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(request.getRefreshToken());
        UserAccount user = resolveRefreshUser(claims);
        LOG.debug("List active sessions requested userId={}", user.getId());

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
        Instant now = Instant.now();
        LOG.info("Session revoke requested userId={} targetSessionId={}", user.getId(), request.sessionId());

        UserSession session = userSessionRepository
                .findByIdAndUserId(request.sessionId(), user.getId())
                .orElseThrow(() -> new BadRequestException("Session not found"));

        if(session.getRevokedAt() != null || session.getExpiresAt().isBefore(now)) {
            LOG.info("Session already inactive targetSessionId={}", session.getId());
            return new ApiMessageResponse("Session is already inactive");
        }

        session.setRevokedAt(now);
        session.setRevokeReason("MANUAL_REVOKE");
        session.setLastSeenAt(now);
        userSessionRepository.save(session);
        LOG.info("Session revoked targetSessionId={} userId={}", session.getId(), user.getId());
        auditService.recordSafely(auditService.build(
            AuditEventType.SESSION_REVOKED,
            AuditOutcome.SUCCESS,
            AuditSeverity.MEDIUM,
            user.getId(),
            user.getEmail(),
            "session",
            session.getId().toString(),
            "revoke_session",
            "auth",
            null,
            null,
            "manual_revoke"
        ));
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
        LOG.info("Password reset initiation requested email={}", normalizedEmail);
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
        resetPasswordEmailService.sendPasswordResetEmail(user.getEmail(), resetToken);
        LOG.info("Password reset token issued userId={} email={}", user.getId(), normalizedEmail);
        auditService.recordSafely(auditService.build(
            AuditEventType.PASSWORD_RESET_REQUESTED,
            AuditOutcome.SUCCESS,
            AuditSeverity.MEDIUM,
            user.getId(),
            user.getEmail(),
            "password_reset_token",
            resetTokenEntity.getId().toString(),
            "request_password_reset",
            "auth",
            null,
            null,
            null
        ));
        return new ApiMessageResponse("Password reset link sent to email");
    }

    /**
     * Reset password using reset token
     */
    @Transactional
    public ApiMessageResponse resetPassword(String resetToken, String newPassword, String confirmPassword) {
        if(!newPassword.equals(confirmPassword)) {
            throw new BadRequestException("Passwords do not match");
        }

        String tokenHash = hashToken(resetToken);
        LOG.info("Password reset verification requested");

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
        LOG.info("Password reset completed userId={} tokenVersion={}", user.getId(), user.getTokenVersion());
        auditService.recordSafely(auditService.build(
            AuditEventType.PASSWORD_RESET_COMPLETED,
            AuditOutcome.SUCCESS,
            AuditSeverity.HIGH,
            user.getId(),
            user.getEmail(),
            "user",
            user.getId().toString(),
            "reset_password",
            "auth",
            null,
            null,
            "sessions_revoked"
        ));

        return new ApiMessageResponse("Password has been reset successfully");
    }

    /**
     * Resend email verification token
     */
    @Transactional
    public ApiMessageResponse resendEmailVerification(String email) {
        String normalizedEmail = normalizeEmail(email);
        LOG.info("Resend verification requested email={}", normalizedEmail);
        UserAccount user = userAccountRepository.findByEmailIgnoreCase(normalizedEmail).orElse(null);

        // Do not reveal whether an account exists.
        if(user == null) {
            LOG.info("Resend verification completed for unknown account email={}", normalizedEmail);
            return new ApiMessageResponse("Verification email sent");
        }

        if(user.isEmailVerified()) {
            LOG.info("Resend verification skipped because email already verified userId={} email={}", user.getId(), normalizedEmail);
            return new ApiMessageResponse("Email is already verified");
        }

        String verificationToken = issueEmailVerificationToken(user);
        verificationEmailService.sendVerificationEmail(user.getEmail(), verificationToken);
        LOG.info("Resend verification completed userId={} email={}", user.getId(), normalizedEmail);
        auditService.recordSafely(auditService.build(
            AuditEventType.EMAIL_VERIFICATION_SENT,
            AuditOutcome.SUCCESS,
            AuditSeverity.LOW,
            user.getId(),
            user.getEmail(),
            "email_verification_token",
            user.getId().toString(),
            "resend_verification",
            "auth",
            null,
            null,
            null
        ));
        return new ApiMessageResponse("Verification email sent");
    }

    /**
     * Verify email using verification token
     */
    @Transactional
    public ApiMessageResponse verifyEmail(String verificationToken) {
        String tokenHash = hashToken(verificationToken);
        LOG.info("Email verification requested");

        EmailVerificationToken tokenEntity = emailVerificationTokenRepository
                .findByTokenHashAndExpiresAtAfter(tokenHash, Instant.now())
                .orElseThrow(() -> new BadRequestException("Invalid or expired verification token"));

        if(tokenEntity.getVerifiedAt() != null) {
            LOG.info("Email verification skipped because token already used userId={}", tokenEntity.getUserId());
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
        LOG.info("Email verified successfully userId={} email={}", user.getId(), user.getEmail());
        auditService.recordSafely(auditService.build(
            AuditEventType.EMAIL_VERIFIED,
            AuditOutcome.SUCCESS,
            AuditSeverity.LOW,
            user.getId(),
            user.getEmail(),
            "user",
            user.getId().toString(),
            "verify_email",
            "auth",
            null,
            null,
            null
        ));

        return new ApiMessageResponse("Email verified successfully");
    }

    @Transactional
    public TokenPairResponse issueTokenPairForUser(UUID userId, ClientContext clientContext) {
        UserAccount user = userAccountRepository
            .findById(userId)
            .orElseThrow(() -> new UnauthorizedException("User not found"));
        LOG.info("Issue token pair requested userId={} ip={}", user.getId(), clientContext == null ? "unknown" : clientContext.ipAddress());

        validateAccountState(user);
        user.setFailedLoginCount(0);
        user.setLockedUntil(null);
        userAccountRepository.save(user);

        return generateTokenPair(user, clientContext == null ? ClientContext.unknown() : clientContext);
    }

    private void validateAccountState(UserAccount user) {
        if(user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now())) {
            LOG.warn("Account is currently locked userId={} lockedUntil={}", user.getId(), user.getLockedUntil());
            throw new AccountLockedException("Account temporarily locked due to failed login attempts");
        }

        if(user.getStatus() == UserStatus.DISABLED) {
            LOG.warn("Account is disabled userId={}", user.getId());
            throw new UnauthorizedException("Account is disabled");
        }

        if(!user.isEmailVerified()) {
            LOG.warn("Login denied because email is not verified userId={} email={}", user.getId(), user.getEmail());
            throw new UnauthorizedException("Email verification required. Please check your inbox for verification link.");
        }
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
        LOG.debug("Session persisted sessionId={} userId={} device={}", session.getId(), userId, session.getDeviceName());
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

    private String issueEmailVerificationToken(UserAccount user) {
        String verificationToken = generateSecureToken();
        String tokenHash = hashToken(verificationToken);

        emailVerificationTokenRepository
            .findByUserIdAndVerifiedAtIsNull(user.getId())
            .ifPresent(emailVerificationTokenRepository::delete);

        EmailVerificationToken tokenEntity = new EmailVerificationToken();
        tokenEntity.setId(UUID.randomUUID());
        tokenEntity.setUserId(user.getId());
        tokenEntity.setEmail(user.getEmail());
        tokenEntity.setTokenHash(tokenHash);
        tokenEntity.setExpiresAt(Instant.now().plusSeconds(emailVerificationTokenProperties.expirySeconds()));
        emailVerificationTokenRepository.save(tokenEntity);

        return verificationToken;
    }

    private String sanitize(String value, int maxLength, String fallback) {
        if(value == null || value.isBlank()) {
            return fallback;
        }
        return value.length() > maxLength ? value.substring(0, maxLength) : value;
    }

    private void assertRateLimit(String scope, String key, int limitPerMinute) {
        if(!authRateLimiter.allow(scope, key, limitPerMinute)) {
            LOG.warn("Rate limit exceeded scope={} key={} limitPerMinute={}", scope, key, limitPerMinute);
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
        //withoutPadding() for removing trailing '==' which are not URL safe and not needed for url use case
    }
}
