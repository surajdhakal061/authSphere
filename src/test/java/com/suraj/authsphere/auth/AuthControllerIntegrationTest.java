package com.suraj.authsphere.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.suraj.authsphere.auth.dto.LoginRequest;
import com.suraj.authsphere.auth.dto.RefreshTokenRequest;
import com.suraj.authsphere.auth.dto.RevokeSessionRequest;
import com.suraj.authsphere.auth.dto.RegisterRequest;
import com.suraj.authsphere.auth.dto.SessionSummaryResponse;
import com.suraj.authsphere.auth.dto.TokenPairResponse;
import com.suraj.authsphere.auth.service.AuthService;
import com.suraj.authsphere.common.exception.UnauthorizedException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AuthControllerIntegrationTest {

    @Autowired
    private AuthService authService;

    @Test
    void registerAndLoginReturnsTokenPairs() {
        TokenPairResponse registerResponse = authService.register(new RegisterRequest("user1@example.com", "Strong@123"));
        TokenPairResponse loginResponse = authService.login(new LoginRequest("user1@example.com", "Strong@123"));

        assertThat(registerResponse.accessToken()).isNotBlank();
        assertThat(registerResponse.refreshToken()).isNotBlank();
        assertThat(loginResponse.accessToken()).isNotBlank();
        assertThat(loginResponse.refreshToken()).isNotBlank();
        assertThat(loginResponse.accessTokenExpiresInSeconds()).isEqualTo(900);
    }

    @Test
    void refreshRotationInvalidatesOldRefreshToken() {
        authService.register(new RegisterRequest("user2@example.com", "Strong@123"));
        TokenPairResponse loginResponse = authService.login(new LoginRequest("user2@example.com", "Strong@123"));

        TokenPairResponse rotated = authService.refresh(new RefreshTokenRequest(loginResponse.refreshToken()));

        assertThat(rotated.refreshToken()).isNotBlank();
        assertThat(rotated.refreshToken()).isNotEqualTo(loginResponse.refreshToken());

        assertThatThrownBy(() -> authService.refresh(new RefreshTokenRequest(loginResponse.refreshToken())))
            .isInstanceOf(UnauthorizedException.class)
            .hasMessageContaining("no longer valid");
    }

    @Test
    void listSessionsAndRevokeSpecificSession() {
        authService.register(new RegisterRequest("user3@example.com", "Strong@123"));
        TokenPairResponse loginResponse = authService.login(new LoginRequest("user3@example.com", "Strong@123"));

        List<SessionSummaryResponse> sessions = authService.listActiveSessions(new RefreshTokenRequest(loginResponse.refreshToken()));

        assertThat(sessions).hasSize(2);
        SessionSummaryResponse targetSession = sessions.stream().filter(s -> !s.currentSession()).findFirst().orElseThrow();

        authService.revokeSession(new RevokeSessionRequest(loginResponse.refreshToken(), targetSession.sessionId()));

        List<SessionSummaryResponse> afterRevoke = authService.listActiveSessions(new RefreshTokenRequest(loginResponse.refreshToken()));
        assertThat(afterRevoke).hasSize(1);
    }
}

