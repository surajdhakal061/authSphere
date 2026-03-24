package com.suraj.authsphere.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record RevokeSessionRequest(
    @NotBlank String refreshToken,
    @NotNull UUID sessionId
) {
}

