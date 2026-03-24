package com.suraj.authsphere.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.suraj.authsphere.auth.dto.LoginRequest;
import com.suraj.authsphere.auth.dto.RegisterRequest;
import com.suraj.authsphere.auth.dto.TokenPairResponse;
import com.suraj.authsphere.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AuthControllerIntegrationTest {

    @Autowired
    private AuthService authService;

    @Test
    void registerAndLoginReturnsTokenPairs() throws Exception {
        TokenPairResponse registerResponse = authService.register(new RegisterRequest("user1@example.com", "Strong@123"));
        TokenPairResponse loginResponse = authService.login(new LoginRequest("user1@example.com", "Strong@123"));

        assertThat(registerResponse.accessToken()).isNotBlank();
        assertThat(registerResponse.refreshToken()).isNotBlank();
        assertThat(loginResponse.accessToken()).isNotBlank();
        assertThat(loginResponse.refreshToken()).isNotBlank();
        assertThat(loginResponse.accessTokenExpiresInSeconds()).isEqualTo(900);
    }
}

