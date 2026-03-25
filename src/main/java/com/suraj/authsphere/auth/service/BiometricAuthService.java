package com.suraj.authsphere.auth.service;

import com.suraj.authsphere.auth.config.AuthRateLimitProperties;
import com.suraj.authsphere.auth.domain.BiometricChallenge;
import com.suraj.authsphere.auth.domain.BiometricChallenge.ChallengePurpose;
import com.suraj.authsphere.auth.domain.BiometricCredential;
import com.suraj.authsphere.auth.domain.UserAccount;
import com.suraj.authsphere.auth.dto.ApiMessageResponse;
import com.suraj.authsphere.auth.dto.BiometricCredentialResponse;
import com.suraj.authsphere.auth.dto.BiometricLoginOptionsRequest;
import com.suraj.authsphere.auth.dto.BiometricLoginOptionsResponse;
import com.suraj.authsphere.auth.dto.BiometricLoginVerifyRequest;
import com.suraj.authsphere.auth.dto.BiometricRegisterOptionsRequest;
import com.suraj.authsphere.auth.dto.BiometricRegisterOptionsResponse;
import com.suraj.authsphere.auth.dto.BiometricRegisterVerifyRequest;
import com.suraj.authsphere.auth.dto.TokenPairResponse;
import com.suraj.authsphere.auth.repository.BiometricChallengeRepository;
import com.suraj.authsphere.auth.repository.BiometricCredentialRepository;
import com.suraj.authsphere.auth.repository.UserAccountRepository;
import com.suraj.authsphere.auth.security.JwtTokenService;
import com.suraj.authsphere.auth.security.JwtTokenService.RefreshTokenClaims;
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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class BiometricAuthService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final long CHALLENGE_TTL_SECONDS = 120;
    private static final Logger LOG = LoggerFactory.getLogger(BiometricAuthService.class);

    private final BiometricCredentialRepository biometricCredentialRepository;
    private final BiometricChallengeRepository biometricChallengeRepository;
    private final UserAccountRepository userAccountRepository;
    private final JwtTokenService jwtTokenService;
    private final AuthService authService;
    private final AuthRateLimiter authRateLimiter;
    private final AuthRateLimitProperties authRateLimitProperties;

    public BiometricAuthService(
        BiometricCredentialRepository biometricCredentialRepository,
        BiometricChallengeRepository biometricChallengeRepository,
        UserAccountRepository userAccountRepository,
        JwtTokenService jwtTokenService,
        AuthService authService,
        AuthRateLimiter authRateLimiter,
        AuthRateLimitProperties authRateLimitProperties
    ) {
        this.biometricCredentialRepository = biometricCredentialRepository;
        this.biometricChallengeRepository = biometricChallengeRepository;
        this.userAccountRepository = userAccountRepository;
        this.jwtTokenService = jwtTokenService;
        this.authService = authService;
        this.authRateLimiter = authRateLimiter;
        this.authRateLimitProperties = authRateLimitProperties;
    }

    @Transactional
    public BiometricRegisterOptionsResponse beginRegistration(BiometricRegisterOptionsRequest request, ClientContext clientContext) {
        assertRateLimit("biometric-register", clientContext.ipAddress(), authRateLimitProperties.biometricRegisterMaxPerMinute());

        UserAccount user = resolveUserFromRefreshToken(request.refreshToken());
        LOG.info("Biometric registration options requested userId={} ip={}", user.getId(), clientContext.ipAddress());
        cleanupExpiredChallenges();

        BiometricChallenge challenge = new BiometricChallenge();
        challenge.setId(UUID.randomUUID());
        challenge.setUserId(user.getId());
        challenge.setPurpose(ChallengePurpose.ENROLL);
        challenge.setChallengeValue(generateSecureToken());
        challenge.setExpiresAt(Instant.now().plusSeconds(CHALLENGE_TTL_SECONDS));
        biometricChallengeRepository.save(challenge);
        LOG.debug("Biometric enroll challenge issued challengeId={} userId={}", challenge.getId(), user.getId());

        return new BiometricRegisterOptionsResponse(challenge.getId(), challenge.getChallengeValue(), challenge.getExpiresAt());
    }

    @Transactional
    public ApiMessageResponse finishRegistration(BiometricRegisterVerifyRequest request) {
        UserAccount user = resolveUserFromRefreshToken(request.refreshToken());
        LOG.info("Biometric registration verification requested userId={}", user.getId());

        BiometricChallenge challenge = biometricChallengeRepository
            .findByIdAndUserId(request.challengeId(), user.getId())
            .orElseThrow(() -> new BadRequestException("Biometric challenge not found"));

        validateChallenge(challenge, ChallengePurpose.ENROLL);

        if (biometricCredentialRepository.existsByCredentialId(request.credentialId())) {
            LOG.warn("Biometric registration denied because credential already exists userId={}", user.getId());
            throw new BadRequestException("Credential ID is already registered");
        }

        String expectedProof = computeProof(challenge.getChallengeValue(), request.credentialId(), request.publicKey());
        if (!expectedProof.equals(request.clientProof())) {
            LOG.warn("Biometric registration proof mismatch userId={} challengeId={}", user.getId(), challenge.getId());
            throw new UnauthorizedException("Invalid biometric proof");
        }

        BiometricCredential credential = new BiometricCredential();
        credential.setId(UUID.randomUUID());
        credential.setUserId(user.getId());
        credential.setCredentialId(request.credentialId());
        credential.setPublicKey(request.publicKey());
        credential.setCredentialName(sanitize(request.credentialName(), 120, "biometric-device"));
        credential.setSignCount(0L);
        biometricCredentialRepository.save(credential);

        challenge.setUsedAt(Instant.now());
        biometricChallengeRepository.save(challenge);
        LOG.info("Biometric credential enrolled userId={} credentialRecordId={}", user.getId(), credential.getId());

        return new ApiMessageResponse("Biometric credential enrolled successfully");
    }

    @Transactional(readOnly = true)
    public List<BiometricCredentialResponse> listCredentials(String refreshToken) {
        UserAccount user = resolveUserFromRefreshToken(refreshToken);
        LOG.debug("List biometric credentials requested userId={}", user.getId());
        return biometricCredentialRepository.findByUserIdAndRevokedAtIsNull(user.getId())
            .stream()
            .map(credential -> new BiometricCredentialResponse(
                credential.getId(),
                credential.getCredentialId(),
                credential.getCredentialName(),
                credential.getSignCount(),
                credential.getLastUsedAt(),
                credential.getCreatedAt()
            ))
            .toList();
    }

    @Transactional
    public ApiMessageResponse revokeCredential(String refreshToken, UUID credentialRecordId) {
        UserAccount user = resolveUserFromRefreshToken(refreshToken);
        LOG.info("Biometric credential revoke requested userId={} credentialRecordId={}", user.getId(), credentialRecordId);

        BiometricCredential credential = biometricCredentialRepository
            .findById(credentialRecordId)
            .orElseThrow(() -> new BadRequestException("Biometric credential not found"));

        if (!credential.getUserId().equals(user.getId())) {
            LOG.warn("Biometric credential revoke denied due to ownership mismatch requesterUserId={} credentialUserId={}", user.getId(), credential.getUserId());
            throw new UnauthorizedException("Credential does not belong to user");
        }

        if (credential.getRevokedAt() != null) {
            LOG.info("Biometric credential already revoked credentialRecordId={}", credential.getId());
            return new ApiMessageResponse("Biometric credential already revoked");
        }

        credential.setRevokedAt(Instant.now());
        biometricCredentialRepository.save(credential);
        LOG.info("Biometric credential revoked credentialRecordId={} userId={}", credential.getId(), user.getId());
        return new ApiMessageResponse("Biometric credential revoked successfully");
    }

    @Transactional
    public BiometricLoginOptionsResponse beginAuthentication(BiometricLoginOptionsRequest request, ClientContext clientContext) {
        assertRateLimit("biometric-login", clientContext.ipAddress(), authRateLimitProperties.biometricLoginMaxPerMinute());
        String normalizedEmail = normalizeEmail(request.email());
        LOG.info("Biometric login options requested email={} ip={}", normalizedEmail, clientContext.ipAddress());

        UserAccount user = userAccountRepository
            .findByEmailIgnoreCase(normalizedEmail)
            .orElseThrow(() -> new UnauthorizedException("Biometric authentication unavailable"));

        List<BiometricCredential> credentials = biometricCredentialRepository.findByUserIdAndRevokedAtIsNull(user.getId());
        if (credentials.isEmpty()) {
            LOG.warn("Biometric login options denied because no active credentials userId={} email={}", user.getId(), normalizedEmail);
            throw new BadRequestException("No biometric credentials enrolled");
        }

        cleanupExpiredChallenges();

        BiometricChallenge challenge = new BiometricChallenge();
        challenge.setId(UUID.randomUUID());
        challenge.setUserId(user.getId());
        challenge.setPurpose(ChallengePurpose.AUTHENTICATE);
        challenge.setChallengeValue(generateSecureToken());
        challenge.setExpiresAt(Instant.now().plusSeconds(CHALLENGE_TTL_SECONDS));
        biometricChallengeRepository.save(challenge);
        LOG.debug("Biometric auth challenge issued challengeId={} userId={}", challenge.getId(), user.getId());

        List<String> credentialIds = credentials.stream().map(BiometricCredential::getCredentialId).toList();
        return new BiometricLoginOptionsResponse(challenge.getId(), challenge.getChallengeValue(), challenge.getExpiresAt(), credentialIds);
    }

    @Transactional
    public TokenPairResponse finishAuthentication(BiometricLoginVerifyRequest request, ClientContext clientContext) {
        String normalizedEmail = normalizeEmail(request.email());
        LOG.info("Biometric login verification requested email={} ip={}", normalizedEmail, clientContext.ipAddress());
        UserAccount user = userAccountRepository
            .findByEmailIgnoreCase(normalizedEmail)
            .orElseThrow(() -> new UnauthorizedException("Biometric authentication failed"));

        BiometricChallenge challenge = biometricChallengeRepository
            .findByIdAndUserId(request.challengeId(), user.getId())
            .orElseThrow(() -> new UnauthorizedException("Invalid biometric challenge"));

        validateChallenge(challenge, ChallengePurpose.AUTHENTICATE);

        BiometricCredential credential = biometricCredentialRepository
            .findByCredentialId(request.credentialId())
            .orElseThrow(() -> new UnauthorizedException("Biometric credential not found"));

        if (!credential.getUserId().equals(user.getId()) || credential.getRevokedAt() != null) {
            LOG.warn("Biometric login denied because credential inactive or ownership mismatch userId={} credentialRecordId={}", user.getId(), credential.getId());
            throw new UnauthorizedException("Biometric credential is not active");
        }

        String expectedProof = computeProof(challenge.getChallengeValue(), request.credentialId(), credential.getPublicKey());
        if (!expectedProof.equals(request.clientProof())) {
            LOG.warn("Biometric login denied due to proof mismatch userId={} challengeId={}", user.getId(), challenge.getId());
            throw new UnauthorizedException("Invalid biometric proof");
        }

        challenge.setUsedAt(Instant.now());
        biometricChallengeRepository.save(challenge);

        credential.setSignCount(credential.getSignCount() + 1);
        credential.setLastUsedAt(Instant.now());
        biometricCredentialRepository.save(credential);
        LOG.info("Biometric login successful userId={} credentialRecordId={}", user.getId(), credential.getId());

        return authService.issueTokenPairForUser(user.getId(), clientContext);
    }

    private void validateChallenge(BiometricChallenge challenge, ChallengePurpose expectedPurpose) {
        if (challenge.getPurpose() != expectedPurpose) {
            throw new UnauthorizedException("Challenge purpose mismatch");
        }
        if (challenge.getUsedAt() != null) {
            throw new UnauthorizedException("Challenge already used");
        }
        if (challenge.getExpiresAt().isBefore(Instant.now())) {
            throw new UnauthorizedException("Challenge expired");
        }
    }

    private UserAccount resolveUserFromRefreshToken(String refreshToken) {
        RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(refreshToken);
        UserAccount user = userAccountRepository
            .findById(claims.userId())
            .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));

        if (!claims.tokenVersion().equals(user.getTokenVersion())) {
            throw new UnauthorizedException("Refresh token is no longer valid");
        }
        return user;
    }

    private void assertRateLimit(String scope, String key, int limitPerMinute) {
        if (!authRateLimiter.allow(scope, key, limitPerMinute)) {
            LOG.warn("Rate limit exceeded scope={} key={} limitPerMinute={}", scope, key, limitPerMinute);
            throw new TooManyRequestsException("Too many requests. Please try again later.");
        }
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String sanitize(String value, int maxLength, String fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return value.length() > maxLength ? value.substring(0, maxLength) : value;
    }

    private String generateSecureToken() {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private String computeProof(String challenge, String credentialId, String secretMaterial) {
        String raw = challenge + ":" + credentialId + ":" + secretMaterial;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    private void cleanupExpiredChallenges() {
        biometricChallengeRepository.deleteByExpiresAtBefore(Instant.now());
        LOG.debug("Expired biometric challenges cleanup executed");
    }
}

