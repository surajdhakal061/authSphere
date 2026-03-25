package com.suraj.authsphere.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.UUID;

public record BiometricRegisterVerifyRequest(
    @NotBlank String refreshToken,
    @NotNull UUID challengeId,
    @NotBlank @Size(max = 128) String credentialId,
    @NotBlank @Size(max = 512) String publicKey,
    String credentialName,
    @NotBlank String clientProof
) {
}
