package com.suraj.authsphere.authorization.dto;

import java.util.List;
import java.util.UUID;

public record UserPermissionsResponse(
    UUID userId,
    List<String> roles,
    List<String> permissions
) {
}

