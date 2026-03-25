package com.suraj.authsphere.authorization.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateRoleRequest(
    @NotBlank
    @Size(min = 3, max = 50)
    String name,
    
    @Size(max = 255)
    String description
) {
}

