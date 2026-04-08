package com.suraj.authsphere.audit.dto;

import com.suraj.authsphere.audit.domain.AuditEventType;
import java.util.Map;

public record AuditEventSummaryResponse(
    long total,
    long successCount,
    long failureCount,
    long blockedCount,
    Map<AuditEventType, Long> byEventType
) {
}

