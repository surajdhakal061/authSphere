package com.suraj.authsphere.authorization.dto;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record AssignRoleRequest(
    @NotNull UUID userId,
    @NotNull UUID roleId
) {
}

