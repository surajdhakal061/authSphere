package com.suraj.authsphere.auth.security;

import com.suraj.authsphere.auth.config.JwtProperties;
import com.suraj.authsphere.auth.domain.UserAccount;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

@Service
public class JwtTokenService {

    private final JwtProperties jwtProperties;

    public JwtTokenService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public String generateAccessToken(UserAccount user) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(jwtProperties.accessTokenTtlSeconds());
        return Jwts.builder()
            .subject(user.getId().toString())
            .claim("email", user.getEmail())
            .claim("type", "access")
            .claim("tokenVersion", user.getTokenVersion())
            .issuedAt(Date.from(now))
            .expiration(Date.from(expiry))
            .id(UUID.randomUUID().toString())
            .signWith(accessKey())
            .compact();
    }

    public String generateRefreshToken(UserAccount user) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(jwtProperties.refreshTokenTtlSeconds());
        return Jwts.builder()
            .subject(user.getId().toString())
            .claim("email", user.getEmail())
            .claim("type", "refresh")
            .claim("tokenVersion", user.getTokenVersion())
            .issuedAt(Date.from(now))
            .expiration(Date.from(expiry))
            .id(UUID.randomUUID().toString())
            .signWith(refreshKey())
            .compact();
    }

    private SecretKey accessKey() {
        return Keys.hmacShaKeyFor(jwtProperties.accessSecret().getBytes(StandardCharsets.UTF_8));
    }

    private SecretKey refreshKey() {
        return Keys.hmacShaKeyFor(jwtProperties.refreshSecret().getBytes(StandardCharsets.UTF_8));
    }
}

