package com.suraj.authsphere.auth.service;

import java.time.Clock;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.stereotype.Component;

@Component
public class AuthRateLimiter {

    private static final long WINDOW_MILLIS = 60_000L;

    private final ConcurrentMap<String, WindowCounter> counters = new ConcurrentHashMap<>();
    private final Clock clock;

    public AuthRateLimiter() {
        this(Clock.systemUTC());
    }

    AuthRateLimiter(Clock clock) {
        this.clock = clock;
    }

    public boolean allow(String scope, String key, int limitPerMinute) {
        if (limitPerMinute <= 0) {
            return true;
        }

        String normalizedKey = scope + ":" + (key == null || key.isBlank() ? "unknown" : key.trim());
        long now = clock.millis();

        WindowCounter result = counters.compute(normalizedKey, (k, existing) -> {
            if (existing == null || now - existing.windowStartMillis >= WINDOW_MILLIS) {
                return new WindowCounter(now, 1);
            }
            existing.count++;
            return existing;
        });

        return result.count <= limitPerMinute;
    }

    private static final class WindowCounter {

        private final long windowStartMillis;
        private int count;

        private WindowCounter(long windowStartMillis, int count) {
            this.windowStartMillis = windowStartMillis;
            this.count = count;
        }
    }
}

