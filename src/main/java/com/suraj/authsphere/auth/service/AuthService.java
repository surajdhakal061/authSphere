package com.suraj.authsphere.auth.service;

import com.suraj.authsphere.auth.config.JwtProperties;
import com.suraj.authsphere.auth.domain.UserAccount;
import com.suraj.authsphere.auth.domain.UserStatus;
import com.suraj.authsphere.auth.dto.LoginRequest;
import com.suraj.authsphere.auth.dto.RegisterRequest;
import com.suraj.authsphere.auth.dto.TokenPairResponse;
import com.suraj.authsphere.auth.repository.UserAccountRepository;
import com.suraj.authsphere.auth.security.JwtTokenService;
import com.suraj.authsphere.common.exception.AccountLockedException;
import com.suraj.authsphere.common.exception.BadRequestException;
import com.suraj.authsphere.common.exception.UnauthorizedException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.UUID;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;

    private final UserAccountRepository userAccountRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;
    private final JwtProperties jwtProperties;

    public AuthService(
        UserAccountRepository userAccountRepository,
        PasswordEncoder passwordEncoder,
        JwtTokenService jwtTokenService,
        JwtProperties jwtProperties
    ) {
        this.userAccountRepository = userAccountRepository;
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
        return new TokenPairResponse(
            jwtTokenService.generateAccessToken(user),
            jwtTokenService.generateRefreshToken(user),
            jwtProperties.accessTokenTtlSeconds(),
            jwtProperties.refreshTokenTtlSeconds()
        );
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}

