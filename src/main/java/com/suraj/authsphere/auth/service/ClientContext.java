package com.suraj.authsphere.auth.service;

public record ClientContext(String ipAddress, String userAgent, String deviceName) {

    public static ClientContext unknown() {
        return new ClientContext("unknown", "unknown", "unknown-device");
    }
}

