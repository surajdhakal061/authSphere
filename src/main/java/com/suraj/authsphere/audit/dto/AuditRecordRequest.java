package com.suraj.authsphere.audit.dto;

import com.suraj.authsphere.audit.domain.AuditEventType;
import com.suraj.authsphere.audit.domain.AuditOutcome;
import com.suraj.authsphere.audit.domain.AuditSeverity;
import java.util.UUID;

public record AuditRecordRequest(
    AuditEventType eventType,
    AuditOutcome outcome,
    AuditSeverity severity,
    UUID actorUserId,
    String actorEmail,
    String targetType,
    String targetId,
    String action,
    String resource,
    String ipAddress,
    String userAgent,
    String correlationId,
    String detailsJson
) {
}

