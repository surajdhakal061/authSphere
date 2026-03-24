package com.suraj.authsphere.auth.dto;

import java.time.Instant;
import java.util.UUID;

public record SessionSummaryResponse(
    UUID sessionId,
    String deviceName,
    String ipAddress,
    String userAgent,
    Instant issuedAt,
    Instant expiresAt,
    boolean currentSession
) {
}

