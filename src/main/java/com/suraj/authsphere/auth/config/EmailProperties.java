package com.suraj.authsphere.auth.config;

import java.io.Serializable;

import lombok.AllArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@ConfigurationProperties(prefix = "auth.email")
public class EmailProperties implements Serializable {
    private boolean enabled;
    private String from;
    private String verificationBaseUrl;
    private String resetBaseUrl;
}
