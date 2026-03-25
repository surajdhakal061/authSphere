package com.suraj.authsphere.auth.controller;

import com.suraj.authsphere.auth.dto.ApiMessageResponse;
import com.suraj.authsphere.auth.dto.BiometricCredentialResponse;
import com.suraj.authsphere.auth.dto.BiometricLoginOptionsRequest;
import com.suraj.authsphere.auth.dto.BiometricLoginOptionsResponse;
import com.suraj.authsphere.auth.dto.BiometricLoginVerifyRequest;
import com.suraj.authsphere.auth.dto.BiometricRegisterOptionsRequest;
import com.suraj.authsphere.auth.dto.BiometricRegisterOptionsResponse;
import com.suraj.authsphere.auth.dto.BiometricRegisterVerifyRequest;
import com.suraj.authsphere.auth.dto.ForgotPasswordRequest;
import com.suraj.authsphere.auth.dto.LoginRequest;
import com.suraj.authsphere.auth.dto.RefreshTokenRequest;
import com.suraj.authsphere.auth.dto.ResetPasswordRequest;
import com.suraj.authsphere.auth.dto.RevokeSessionRequest;
import com.suraj.authsphere.auth.dto.RegisterRequest;
import com.suraj.authsphere.auth.dto.SessionSummaryResponse;
import com.suraj.authsphere.auth.dto.TokenPairResponse;
import com.suraj.authsphere.auth.dto.VerifyEmailRequest;
import com.suraj.authsphere.auth.service.BiometricAuthService;
import com.suraj.authsphere.auth.service.ClientContext;
import com.suraj.authsphere.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final BiometricAuthService biometricAuthService;

    public AuthController(AuthService authService, BiometricAuthService biometricAuthService) {
        this.authService = authService;
        this.biometricAuthService = biometricAuthService;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ApiMessageResponse register(@Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
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

    @GetMapping("/sessions")
    public List<SessionSummaryResponse> listActiveSessions(@RequestHeader("X-Refresh-Token") String refreshToken) {
        return authService.listActiveSessions(new RefreshTokenRequest(refreshToken));
    }

    @PostMapping("/sessions/revoke")
    public ApiMessageResponse revokeSession(@Valid @RequestBody RevokeSessionRequest request) {
        return authService.revokeSession(request);
    }

    @DeleteMapping("/sessions/{sessionId}")
    public ApiMessageResponse revokeSession(
        @PathVariable("sessionId") UUID sessionId,
        @RequestHeader("X-Refresh-Token") String refreshToken
    ) {
        return authService.revokeSession(refreshToken, sessionId);
    }

    @PostMapping("/forgot-password")
    public ApiMessageResponse forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        return authService.initiatePasswordReset(request.email());
    }

    @PostMapping("/reset-password")
    public ApiMessageResponse resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        return authService.resetPassword(request.token(), request.newPassword());
    }

    @PostMapping("/verify-email")
    public ApiMessageResponse verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        return authService.verifyEmail(request.token());
    }

    @GetMapping("/verify-email")
    public ApiMessageResponse verifyEmailByLink(@RequestParam("token") String token) {
        return authService.verifyEmail(token);
    }

    @PostMapping("/resend-verification")
    public ApiMessageResponse resendVerification(@Valid @RequestBody ForgotPasswordRequest request) {
        return authService.resendEmailVerification(request.email());
    }

    @GetMapping("/health")
    public String health() {
        return "auth-service-up";
    }

    @PostMapping("/biometric/register/options")
    public BiometricRegisterOptionsResponse biometricRegisterOptions(
        @Valid @RequestBody BiometricRegisterOptionsRequest request,
        HttpServletRequest httpRequest
    ) {
        return biometricAuthService.beginRegistration(request, toClientContext(httpRequest));
    }

    @PostMapping("/biometric/register/verify")
    public ApiMessageResponse biometricRegisterVerify(@Valid @RequestBody BiometricRegisterVerifyRequest request) {
        return biometricAuthService.finishRegistration(request);
    }

    @PostMapping("/biometric/login/options")
    public BiometricLoginOptionsResponse biometricLoginOptions(
        @Valid @RequestBody BiometricLoginOptionsRequest request,
        HttpServletRequest httpRequest
    ) {
        return biometricAuthService.beginAuthentication(request, toClientContext(httpRequest));
    }

    @PostMapping("/biometric/login/verify")
    public TokenPairResponse biometricLoginVerify(
        @Valid @RequestBody BiometricLoginVerifyRequest request,
        HttpServletRequest httpRequest
    ) {
        return biometricAuthService.finishAuthentication(request, toClientContext(httpRequest));
    }

    @GetMapping("/biometric/credentials")
    public List<BiometricCredentialResponse> listBiometricCredentials(
        @RequestHeader("X-Refresh-Token") String refreshToken
    ) {
        return biometricAuthService.listCredentials(refreshToken);
    }

    @DeleteMapping("/biometric/credentials/{credentialRecordId}")
    public ApiMessageResponse revokeBiometricCredential(
        @PathVariable("credentialRecordId") java.util.UUID credentialRecordId,
        @RequestHeader("X-Refresh-Token") String refreshToken
    ) {
        return biometricAuthService.revokeCredential(refreshToken, credentialRecordId);
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

