package com.suraj.authsphere.auth.controller;

import com.suraj.authsphere.auth.dto.ApiMessageResponse;
import com.suraj.authsphere.auth.dto.LoginRequest;
import com.suraj.authsphere.auth.dto.RefreshTokenRequest;
import com.suraj.authsphere.auth.dto.RevokeSessionRequest;
import com.suraj.authsphere.auth.dto.RegisterRequest;
import com.suraj.authsphere.auth.dto.SessionSummaryResponse;
import com.suraj.authsphere.auth.dto.TokenPairResponse;
import com.suraj.authsphere.auth.service.ClientContext;
import com.suraj.authsphere.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public TokenPairResponse register(@Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
        return authService.register(request, toClientContext(httpRequest));
    }

    @PostMapping("/login")
    public TokenPairResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        return authService.login(request, toClientContext(httpRequest));
    }

    @PostMapping("/refresh")
    public TokenPairResponse refresh(@Valid @RequestBody RefreshTokenRequest request, HttpServletRequest httpRequest) {
        return authService.refresh(request, toClientContext(httpRequest));
    }

    @PostMapping("/logout")
    public ApiMessageResponse logout(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.logout(request);
    }

    @PostMapping("/logout-all")
    public ApiMessageResponse logoutAll(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.logoutAll(request);
    }

    @PostMapping("/sessions")
    public List<SessionSummaryResponse> listActiveSessions(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.listActiveSessions(request);
    }

    @PostMapping("/sessions/revoke")
    public ApiMessageResponse revokeSession(@Valid @RequestBody RevokeSessionRequest request) {
        return authService.revokeSession(request);
    }

    @GetMapping("/health")
    public String health() {
        return "auth-service-up";
    }

    private ClientContext toClientContext(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        String ipAddress = forwarded == null || forwarded.isBlank()
            ? request.getRemoteAddr()
            : forwarded.split(",")[0].trim();
        String userAgent = Optional.ofNullable(request.getHeader("User-Agent")).orElse("unknown");
        String deviceName = Optional.ofNullable(request.getHeader("X-Device-Name")).orElse(userAgent);
        return new ClientContext(ipAddress, userAgent, deviceName);
    }
}

