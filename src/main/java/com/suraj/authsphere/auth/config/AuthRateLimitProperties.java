package com.suraj.authsphere.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.rate-limit")
public record AuthRateLimitProperties(
    int loginMaxPerMinute,
    int refreshMaxPerMinute,
    int biometricRegisterMaxPerMinute,
    int biometricLoginMaxPerMinute
) {
}
