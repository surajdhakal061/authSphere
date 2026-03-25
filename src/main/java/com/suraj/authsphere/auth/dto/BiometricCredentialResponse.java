package com.suraj.authsphere.auth.dto;

import java.time.Instant;
import java.util.UUID;

public record BiometricCredentialResponse(
    UUID id,
    String credentialId,
    String credentialName,
    long signCount,
    Instant lastUsedAt,
    Instant createdAt
) {
}

