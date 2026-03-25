package com.suraj.authsphere.auth.dto;

import java.time.Instant;
import java.util.UUID;

public record BiometricRegisterOptionsResponse(
    UUID challengeId,
    String challenge,
    Instant expiresAt
) {
}

