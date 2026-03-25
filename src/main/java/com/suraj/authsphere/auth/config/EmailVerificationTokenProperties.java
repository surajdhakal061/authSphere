package com.suraj.authsphere.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.token-verification")
public record EmailVerificationTokenProperties(long expirySeconds) {
}

