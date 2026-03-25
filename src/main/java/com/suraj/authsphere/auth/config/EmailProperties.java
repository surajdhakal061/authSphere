package com.suraj.authsphere.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.email")
public record EmailProperties(
    boolean enabled,
    String from,
    String verificationBaseUrl
) {
}

