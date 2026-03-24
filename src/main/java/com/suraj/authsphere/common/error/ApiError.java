package com.suraj.authsphere.common.error;

import java.time.Instant;
import java.util.List;

public record ApiError(
    Instant timestamp,
    String path,
    String code,
    String message,
    List<String> details
) {
}

