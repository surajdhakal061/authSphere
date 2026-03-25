package com.suraj.authsphere.authorization.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record RoleResponse(
    UUID id,
    String name,
    String description,
    boolean systemRole,
    List<PermissionResponse> permissions,
    Instant createdAt,
    Instant updatedAt
) {
}

