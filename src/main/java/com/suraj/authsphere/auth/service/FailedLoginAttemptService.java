package com.suraj.authsphere.auth.service;

import com.suraj.authsphere.auth.domain.UserAccount;
import com.suraj.authsphere.auth.repository.UserAccountRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FailedLoginAttemptService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Logger LOG = LoggerFactory.getLogger(FailedLoginAttemptService.class);

    private final UserAccountRepository userAccountRepository;

    public FailedLoginAttemptService(UserAccountRepository userAccountRepository) {
        this.userAccountRepository = userAccountRepository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void registerFailedAttempt(UUID userId) {
        UserAccount user = userAccountRepository.findById(userId).orElse(null);
        if (user == null) {
            LOG.warn("Failed attempt persistence skipped because user was not found userId={}", userId);
            return;
        }

        int nextAttempts = user.getFailedLoginCount() + 1;
        user.setFailedLoginCount(nextAttempts);

        if (nextAttempts >= MAX_FAILED_ATTEMPTS) {
            user.setLockedUntil(Instant.now().plus(15, ChronoUnit.MINUTES));
            user.setFailedLoginCount(0);
            LOG.warn("Account locked after failed attempts userId={} lockMinutes=15", user.getId());
        }

        userAccountRepository.saveAndFlush(user);
    }
}

