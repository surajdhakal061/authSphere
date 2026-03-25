package com.suraj.authsphere.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record BiometricCredentialRevokeRequest(
    @NotBlank String refreshToken,
    @NotNull UUID credentialRecordId
) {
}

