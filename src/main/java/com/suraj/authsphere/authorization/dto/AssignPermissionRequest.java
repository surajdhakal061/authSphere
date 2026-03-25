package com.suraj.authsphere.authorization.dto;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record AssignPermissionRequest(
    @NotNull UUID roleId,
    @NotNull UUID permissionId
) {
}

