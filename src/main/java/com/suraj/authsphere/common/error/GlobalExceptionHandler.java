package com.suraj.authsphere.common.error;

import com.suraj.authsphere.common.exception.AccountLockedException;
import com.suraj.authsphere.common.exception.BadRequestException;
import com.suraj.authsphere.common.exception.TooManyRequestsException;
import com.suraj.authsphere.common.exception.UnauthorizedException;
import com.suraj.authsphere.audit.domain.AuditEventType;
import com.suraj.authsphere.audit.domain.AuditOutcome;
import com.suraj.authsphere.audit.domain.AuditSeverity;
import com.suraj.authsphere.audit.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private final AuditService auditService;

    public GlobalExceptionHandler(AuditService auditService) {
        this.auditService = auditService;
    }

    @ExceptionHandler(BadRequestException.class)
    ResponseEntity<ApiError> handleBadRequest(BadRequestException ex, HttpServletRequest request) {
        LOG.warn("Bad request at path={} message={}", request.getRequestURI(), ex.getMessage());
        auditFailure(request, "AUTH-400", ex.getMessage(), AuditSeverity.LOW);
        return build(HttpStatus.BAD_REQUEST, "AUTH-400", ex.getMessage(), List.of(), request.getRequestURI());
    }

    @ExceptionHandler(UnauthorizedException.class)
    ResponseEntity<ApiError> handleUnauthorized(UnauthorizedException ex, HttpServletRequest request) {
        LOG.warn("Unauthorized request at path={} message={}", request.getRequestURI(), ex.getMessage());
        auditFailure(request, "AUTH-401", ex.getMessage(), AuditSeverity.MEDIUM);
        return build(HttpStatus.UNAUTHORIZED, "AUTH-401", ex.getMessage(), List.of(), request.getRequestURI());
    }

    @ExceptionHandler(AccountLockedException.class)
    ResponseEntity<ApiError> handleAccountLocked(AccountLockedException ex, HttpServletRequest request) {
        LOG.warn("Locked account access attempt at path={} message={}", request.getRequestURI(), ex.getMessage());
        auditFailure(request, "AUTH-423", ex.getMessage(), AuditSeverity.HIGH);
        return build(HttpStatus.LOCKED, "AUTH-423", ex.getMessage(), List.of(), request.getRequestURI());
    }

    @ExceptionHandler(TooManyRequestsException.class)
    ResponseEntity<ApiError> handleTooManyRequests(TooManyRequestsException ex, HttpServletRequest request) {
        LOG.warn("Rate limit exceeded at path={} message={}", request.getRequestURI(), ex.getMessage());
        auditFailure(request, "AUTH-429", ex.getMessage(), AuditSeverity.MEDIUM);
        return build(HttpStatus.TOO_MANY_REQUESTS, "AUTH-429", ex.getMessage(), List.of(), request.getRequestURI());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest request) {
        List<String> details = ex.getBindingResult()
            .getFieldErrors()
            .stream()
            .map(FieldError::getDefaultMessage)
            .collect(Collectors.toList());
        LOG.warn("Validation failed at path={} errors={}", request.getRequestURI(), details.size());
        auditFailure(request, "AUTH-400-VALIDATION", "Validation failed", AuditSeverity.LOW);
        return build(HttpStatus.BAD_REQUEST, "AUTH-400-VALIDATION", "Validation failed", details, request.getRequestURI());
    }

    @ExceptionHandler(ConstraintViolationException.class)
    ResponseEntity<ApiError> handleConstraintViolation(ConstraintViolationException ex, HttpServletRequest request) {
        List<String> details = ex.getConstraintViolations().stream().map(v -> v.getMessage()).toList();
        LOG.warn("Constraint violation at path={} errors={}", request.getRequestURI(), details.size());
        auditFailure(request, "AUTH-400-VALIDATION", "Validation failed", AuditSeverity.LOW);
        return build(HttpStatus.BAD_REQUEST, "AUTH-400-VALIDATION", "Validation failed", details, request.getRequestURI());
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ApiError> handleFallback(Exception ex, HttpServletRequest request) {
        LOG.error("Unhandled exception at path={}", request.getRequestURI(), ex);
        auditFailure(request, "AUTH-500", "Unexpected server error", AuditSeverity.HIGH);
        return build(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "AUTH-500",
            "Unexpected server error",
            List.of(),
            request.getRequestURI()
        );
    }

    private ResponseEntity<ApiError> build(
        HttpStatus status,
        String code,
        String message,
        List<String> details,
        String path
    ) {
        return ResponseEntity.status(status).body(new ApiError(Instant.now(), path, code, message, details));
    }

    private void auditFailure(HttpServletRequest request, String code, String message, AuditSeverity severity) {
        String details = "code=" + code + ",message=" + message;
        auditService.recordSafely(auditService.build(
            AuditEventType.API_REQUEST_FAILED,
            AuditOutcome.FAILURE,
            severity,
            null,
            null,
            "http_request",
            request.getRequestURI(),
            request.getMethod(),
            "api",
            request.getRemoteAddr(),
            request.getHeader("User-Agent"),
            details
        ));
    }
}

