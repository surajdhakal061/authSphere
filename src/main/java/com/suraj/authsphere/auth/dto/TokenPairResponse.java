package com.suraj.authsphere.auth.dto;

public record TokenPairResponse(
    String accessToken,
    String refreshToken,
    long accessTokenExpiresInSeconds,
    long refreshTokenExpiresInSeconds
) {
}

