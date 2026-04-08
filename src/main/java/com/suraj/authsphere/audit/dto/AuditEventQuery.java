package com.suraj.authsphere.audit.dto;

import com.suraj.authsphere.audit.domain.AuditEventType;
import com.suraj.authsphere.audit.domain.AuditOutcome;
import java.time.Instant;
import java.util.UUID;

public record AuditEventQuery(
    AuditEventType eventType,
    AuditOutcome outcome,
    UUID actorUserId,
    String targetType,
    String targetId,
    Instant from,
    Instant to
) {
}

