package com.suraj.authsphere.authorization.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreatePermissionRequest(
    @NotBlank
    @Size(min = 3, max = 100)
    String code,
    
    @NotBlank
    @Size(max = 255)
    String description,
    
    @Size(max = 50)
    String resource,
    
    @Size(max = 50)
    String action
) {
}

