package com.suraj.authsphere.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.jwt")
public record JwtProperties(
    String accessSecret,
    String refreshSecret,
    long accessTokenTtlSeconds,
    long refreshTokenTtlSeconds
) {
}

