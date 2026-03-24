package com.suraj.authsphere.common.error;

import com.suraj.authsphere.common.exception.AccountLockedException;
import com.suraj.authsphere.common.exception.BadRequestException;
import com.suraj.authsphere.common.exception.UnauthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BadRequestException.class)
    ResponseEntity<ApiError> handleBadRequest(BadRequestException ex, HttpServletRequest request) {
        return build(HttpStatus.BAD_REQUEST, "AUTH-400", ex.getMessage(), List.of(), request.getRequestURI());
    }

    @ExceptionHandler(UnauthorizedException.class)
    ResponseEntity<ApiError> handleUnauthorized(UnauthorizedException ex, HttpServletRequest request) {
        return build(HttpStatus.UNAUTHORIZED, "AUTH-401", ex.getMessage(), List.of(), request.getRequestURI());
    }

    @ExceptionHandler(AccountLockedException.class)
    ResponseEntity<ApiError> handleAccountLocked(AccountLockedException ex, HttpServletRequest request) {
        return build(HttpStatus.LOCKED, "AUTH-423", ex.getMessage(), List.of(), request.getRequestURI());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest request) {
        List<String> details = ex.getBindingResult()
            .getFieldErrors()
            .stream()
            .map(FieldError::getDefaultMessage)
            .collect(Collectors.toList());
        return build(HttpStatus.BAD_REQUEST, "AUTH-400-VALIDATION", "Validation failed", details, request.getRequestURI());
    }

    @ExceptionHandler(ConstraintViolationException.class)
    ResponseEntity<ApiError> handleConstraintViolation(ConstraintViolationException ex, HttpServletRequest request) {
        List<String> details = ex.getConstraintViolations().stream().map(v -> v.getMessage()).toList();
        return build(HttpStatus.BAD_REQUEST, "AUTH-400-VALIDATION", "Validation failed", details, request.getRequestURI());
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ApiError> handleFallback(Exception ex, HttpServletRequest request) {
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
}

