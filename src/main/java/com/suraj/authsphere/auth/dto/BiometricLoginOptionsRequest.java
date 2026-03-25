package com.suraj.authsphere.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record BiometricLoginOptionsRequest(
    @NotBlank @Email String email
) {
}

