package com.suraj.authsphere.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.UUID;

public record BiometricLoginVerifyRequest(
    @NotBlank @Email String email,
    @NotNull UUID challengeId,
    @NotBlank @Size(max = 128) String credentialId,
    @NotBlank String clientProof
) {
}

