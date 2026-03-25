package com.suraj.authsphere.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record BiometricRegisterOptionsRequest(
    @NotBlank String refreshToken,
    String credentialName
) {
}

