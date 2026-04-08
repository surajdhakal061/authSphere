package com.suraj.authsphere.audit.dto;

import com.suraj.authsphere.audit.domain.AuditEventType;
import com.suraj.authsphere.audit.domain.AuditOutcome;
import com.suraj.authsphere.audit.domain.AuditSeverity;
import java.time.Instant;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuditEventResponse {
    private UUID id;
    private AuditEventType eventType;
    private AuditOutcome outcome;
    private AuditSeverity severity;
    private UUID actorUserId;
    private String actorEmail;
    private String targetType;
    private String targetId;
    private String action;
    private String resource;
    private String ipAddress;
    private String userAgent;
    private String correlationId;
    private String detailsJson;
    private Instant createdAt;
}

