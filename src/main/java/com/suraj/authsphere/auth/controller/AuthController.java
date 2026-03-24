package com.suraj.authsphere.auth.controller;

import com.suraj.authsphere.auth.dto.ApiMessageResponse;
import com.suraj.authsphere.auth.dto.LoginRequest;
import com.suraj.authsphere.auth.dto.RefreshTokenRequest;
import com.suraj.authsphere.auth.dto.RegisterRequest;
import com.suraj.authsphere.auth.dto.TokenPairResponse;
import com.suraj.authsphere.auth.service.AuthService;
import jakarta.validation.Valid;
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
    public TokenPairResponse register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @PostMapping("/login")
    public TokenPairResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/refresh")
    public TokenPairResponse refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refresh(request);
    }

    @PostMapping("/logout")
    public ApiMessageResponse logout(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.logout(request);
    }

    @PostMapping("/logout-all")
    public ApiMessageResponse logoutAll(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.logoutAll(request);
    }

    @GetMapping("/health")
    public String health() {
        return "auth-service-up";
    }
}

