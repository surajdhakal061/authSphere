package com.suraj.authsphere.authorization.dto;

import java.time.Instant;
import java.util.UUID;

public record PermissionResponse(
    UUID id,
    String code,
    String description,
    String resource,
    String action,
    Instant createdAt,
    Instant updatedAt
) {
}

