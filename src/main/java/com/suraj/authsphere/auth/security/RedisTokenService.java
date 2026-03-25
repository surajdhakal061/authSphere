package com.suraj.authsphere.auth.security;

import java.time.Duration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

/**
 * Service for managing temporary tokens using Redis.
 * Used for password reset and email verification tokens.
 */
@Service
public class RedisTokenService {

    private static final String PASSWORD_RESET_KEY_PREFIX = "auth:password-reset:";
    private static final String EMAIL_VERIFICATION_KEY_PREFIX = "auth:email-verify:";
    private static final String TOKEN_BLACKLIST_KEY_PREFIX = "auth:token-blacklist:";

    private final StringRedisTemplate redisTemplate;

    public RedisTokenService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Store a password reset token with expiry
     */
    public void storePasswordResetToken(String tokenHash, String userId, Duration expiryDuration) {
        String key = PASSWORD_RESET_KEY_PREFIX + tokenHash;
        redisTemplate.opsForValue().set(key, userId, expiryDuration);
    }

    /**
     * Retrieve user ID from password reset token
     */
    public String getPasswordResetToken(String tokenHash) {
        String key = PASSWORD_RESET_KEY_PREFIX + tokenHash;
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * Delete password reset token
     */
    public void deletePasswordResetToken(String tokenHash) {
        String key = PASSWORD_RESET_KEY_PREFIX + tokenHash;
        redisTemplate.delete(key);
    }

    /**
     * Store an email verification token with expiry
     */
    public void storeEmailVerificationToken(String tokenHash, String userId, Duration expiryDuration) {
        String key = EMAIL_VERIFICATION_KEY_PREFIX + tokenHash;
        redisTemplate.opsForValue().set(key, userId, expiryDuration);
    }

    /**
     * Retrieve user ID from email verification token
     */
    public String getEmailVerificationToken(String tokenHash) {
        String key = EMAIL_VERIFICATION_KEY_PREFIX + tokenHash;
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * Delete email verification token
     */
    public void deleteEmailVerificationToken(String tokenHash) {
        String key = EMAIL_VERIFICATION_KEY_PREFIX + tokenHash;
        redisTemplate.delete(key);
    }

    /**
     * Blacklist an access token JTI (for revocation)
     */
    public void blacklistAccessToken(String jti, Duration expiryDuration) {
        String key = TOKEN_BLACKLIST_KEY_PREFIX + jti;
        redisTemplate.opsForValue().set(key, "revoked", expiryDuration);
    }

    /**
     * Check if an access token JTI is blacklisted
     */
    public boolean isAccessTokenBlacklisted(String jti) {
        String key = TOKEN_BLACKLIST_KEY_PREFIX + jti;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }
}

