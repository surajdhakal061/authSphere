package com.suraj.authsphere.auth.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record BiometricLoginOptionsResponse(
    UUID challengeId,
    String challenge,
    Instant expiresAt,
    List<String> credentialIds
) {
}

