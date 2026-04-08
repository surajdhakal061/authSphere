package com.suraj.authsphere.audit.service;

import com.suraj.authsphere.audit.domain.AuditEvent;
import com.suraj.authsphere.audit.domain.AuditEventType;
import com.suraj.authsphere.audit.domain.AuditOutcome;
import com.suraj.authsphere.audit.domain.AuditSeverity;
import com.suraj.authsphere.audit.dto.AuditEventQuery;
import com.suraj.authsphere.audit.dto.AuditEventResponse;
import com.suraj.authsphere.audit.dto.AuditEventSummaryResponse;
import com.suraj.authsphere.audit.dto.AuditRecordRequest;
import com.suraj.authsphere.audit.repository.AuditEventRepository;
import com.suraj.authsphere.auth.domain.UserAccount;
import com.suraj.authsphere.auth.repository.UserAccountRepository;
import com.suraj.authsphere.auth.security.JwtTokenService;
import com.suraj.authsphere.authorization.repository.RolePermissionRepository;
import com.suraj.authsphere.common.exception.UnauthorizedException;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditService {
    
    private static final Logger LOG = LoggerFactory.getLogger(AuditService.class);

    private final AuditEventRepository auditEventRepository;
    private final JwtTokenService jwtTokenService;
    private final UserAccountRepository userAccountRepository;
    private final RolePermissionRepository rolePermissionRepository;

    public AuditService(
        AuditEventRepository auditEventRepository,
        JwtTokenService jwtTokenService,
        UserAccountRepository userAccountRepository,
        RolePermissionRepository rolePermissionRepository
    ) {
        this.auditEventRepository = auditEventRepository;
        this.jwtTokenService = jwtTokenService;
        this.userAccountRepository = userAccountRepository;
        this.rolePermissionRepository = rolePermissionRepository;
    }

    @Transactional
    public void record(AuditRecordRequest request) {
        AuditEvent event = new AuditEvent();
        event.setEventType(request.eventType());
        event.setOutcome(request.outcome());
        event.setSeverity(request.severity());
        event.setActorUserId(request.actorUserId());
        event.setActorEmail(sanitize(request.actorEmail(), 320));
        event.setTargetType(sanitize(request.targetType(), 64));
        event.setTargetId(sanitize(request.targetId(), 128));
        event.setAction(sanitize(request.action(), 120));
        event.setResource(sanitize(request.resource(), 120));
        event.setIpAddress(sanitize(request.ipAddress(), 64));
        event.setUserAgent(sanitize(request.userAgent(), 255));
        event.setCorrelationId(sanitize(request.correlationId(), 100));
        event.setDetailsJson(sanitize(request.detailsJson(), 4000));
        auditEventRepository.save(event);
    }

    @Transactional
    public void recordSafely(AuditRecordRequest request) {
        try {
            record(request);
        } catch (Exception ex) {
            LOG.error("Failed to persist audit event eventType={} outcome={}", request.eventType(), request.outcome(), ex);
        }
    }

    @Transactional(readOnly = true)
    public Page<AuditEventResponse> listEvents(String refreshToken, AuditEventQuery query, Pageable pageable) {
        assertAuditReadPermission(refreshToken);

        Specification<AuditEvent> specification = (root, cq, cb) -> cb.conjunction();
        if (query.eventType() != null) {
            specification = specification.and((root, cq, cb) -> cb.equal(root.get("eventType"), query.eventType()));
        }
        if (query.outcome() != null) {
            specification = specification.and((root, cq, cb) -> cb.equal(root.get("outcome"), query.outcome()));
        }
        if (query.actorUserId() != null) {
            specification = specification.and((root, cq, cb) -> cb.equal(root.get("actorUserId"), query.actorUserId()));
        }
        if (query.targetType() != null && !query.targetType().isBlank()) {
            specification = specification.and((root, cq, cb) -> cb.equal(root.get("targetType"), query.targetType()));
        }
        if (query.targetId() != null && !query.targetId().isBlank()) {
            specification = specification.and((root, cq, cb) -> cb.equal(root.get("targetId"), query.targetId()));
        }
        if (query.from() != null) {
            specification = specification.and((root, cq, cb) -> cb.greaterThanOrEqualTo(root.get("createdAt"), query.from()));
        }
        if (query.to() != null) {
            specification = specification.and((root, cq, cb) -> cb.lessThanOrEqualTo(root.get("createdAt"), query.to()));
        }

        return auditEventRepository.findAll(specification, pageable).map(this::toResponse);
    }

    @Transactional(readOnly = true)
    public AuditEventResponse getById(String refreshToken, UUID id) {
        assertAuditReadPermission(refreshToken);
        AuditEvent event = auditEventRepository.findById(id)
            .orElseThrow(() -> new UnauthorizedException("Audit event not found"));
        return toResponse(event);
    }

    @Transactional(readOnly = true)
    public AuditEventSummaryResponse summarize(String refreshToken, Instant from, Instant to) {
        assertAuditReadPermission(refreshToken);

        AuditEventQuery query = new AuditEventQuery(null, null, null, null, null, from, to);
        Page<AuditEventResponse> page = listEvents(refreshToken, query, Pageable.unpaged());

        long total = page.getTotalElements();
        long successCount = page.stream().filter(event -> event.getOutcome() == AuditOutcome.SUCCESS).count();
        long failureCount = page.stream().filter(event -> event.getOutcome() == AuditOutcome.FAILURE).count();
        long blockedCount = page.stream().filter(event -> event.getOutcome() == AuditOutcome.BLOCKED).count();

        Map<AuditEventType, Long> byEventType = new EnumMap<>(AuditEventType.class);
        page.forEach(event -> byEventType.merge(event.getEventType(), 1L, Long::sum));

        return new AuditEventSummaryResponse(total, successCount, failureCount, blockedCount, byEventType);
    }

    public AuditRecordRequest build(
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
        String detailsJson
    ) {
        return new AuditRecordRequest(
            eventType,
            outcome,
            severity,
            actorUserId,
            actorEmail,
            targetType,
            targetId,
            action,
            resource,
            ipAddress,
            userAgent,
            null,
            detailsJson
        );
    }

    private void assertAuditReadPermission(String refreshToken) {
        JwtTokenService.RefreshTokenClaims claims = jwtTokenService.parseRefreshToken(refreshToken);
        UserAccount actor = userAccountRepository.findById(claims.userId())
            .orElseThrow(() -> new UnauthorizedException("User not found"));

        if (!claims.tokenVersion().equals(actor.getTokenVersion())) {
            throw new UnauthorizedException("Refresh token is no longer valid");
        }

        var permissions = rolePermissionRepository.findPermissionCodesByUserId(actor.getId());
        boolean allowed = permissions.contains("iam.audit.read") || permissions.contains("iam.audit.admin");
        if (!allowed) {
            throw new UnauthorizedException("Insufficient permissions to read audit logs");
        }
    }

    private AuditEventResponse toResponse(AuditEvent event) {
        return new AuditEventResponse(
            event.getId(),
            event.getEventType(),
            event.getOutcome(),
            event.getSeverity(),
            event.getActorUserId(),
            event.getActorEmail(),
            event.getTargetType(),
            event.getTargetId(),
            event.getAction(),
            event.getResource(),
            event.getIpAddress(),
            event.getUserAgent(),
            event.getCorrelationId(),
            event.getDetailsJson(),
            event.getCreatedAt()
        );
    }

    private String sanitize(String value, int maxLength) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.length() > maxLength ? value.substring(0, maxLength) : value;
    }
}

