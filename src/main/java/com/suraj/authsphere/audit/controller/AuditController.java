package com.suraj.authsphere.audit.controller;

import com.suraj.authsphere.audit.domain.AuditEventType;
import com.suraj.authsphere.audit.domain.AuditOutcome;
import com.suraj.authsphere.audit.dto.AuditEventQuery;
import com.suraj.authsphere.audit.dto.AuditEventResponse;
import com.suraj.authsphere.audit.dto.AuditEventSummaryResponse;
import com.suraj.authsphere.audit.service.AuditService;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/audit")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/events")
    public Page<AuditEventResponse> listEvents(
        @RequestHeader("X-Refresh-Token") String refreshToken,
        @RequestParam(value = "eventType", required = false) AuditEventType eventType,
        @RequestParam(value = "outcome", required = false) AuditOutcome outcome,
        @RequestParam(value = "actorUserId", required = false) UUID actorUserId,
        @RequestParam(value = "targetType", required = false) String targetType,
        @RequestParam(value = "targetId", required = false) String targetId,
        @RequestParam(value = "from", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
        @RequestParam(value = "to", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
        Pageable pageable
    ) {
        AuditEventQuery query = new AuditEventQuery(eventType, outcome, actorUserId, targetType, targetId, from, to);
        return auditService.listEvents(refreshToken, query, pageable);
    }

    @GetMapping("/events/{id}")
    public AuditEventResponse getById(
        @RequestHeader("X-Refresh-Token") String refreshToken,
        @PathVariable("id") UUID id
    ) {
        return auditService.getById(refreshToken, id);
    }

    @GetMapping("/events/summary")
    public AuditEventSummaryResponse summary(
        @RequestHeader("X-Refresh-Token") String refreshToken,
        @RequestParam(value = "from", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
        @RequestParam(value = "to", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to
    ) {
        return auditService.summarize(refreshToken, from, to);
    }
}

