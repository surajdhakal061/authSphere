package com.suraj.authsphere.auth.service;

import com.suraj.authsphere.auth.config.EmailProperties;
import com.suraj.authsphere.common.exception.BadRequestException;
import java.net.URLEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

@Service
public class ResetPasswordEmailService {

    private static final Logger LOG = LoggerFactory.getLogger(ResetPasswordEmailService.class);

    private final EmailProperties emailProperties;
    private final JavaMailSender mailSender;

    public ResetPasswordEmailService(EmailProperties emailProperties, JavaMailSender mailSender) {
        this.emailProperties = emailProperties;
        this.mailSender = mailSender;
    }

    public void sendPasswordResetEmail(String recipientEmail, String token) {
        String resetUrl = buildResetUrl(token);

        if (!emailProperties.enabled()) {
            LOG.info("Email sending disabled. Password reset link for {} -> {}", recipientEmail, resetUrl);
            return;
        }

        if (mailSender == null) {
            throw new BadRequestException("Email sender is not configured");
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(emailProperties.from());
            message.setTo(recipientEmail);
            message.setSubject("Reset your AuthSphere password");
            message.setText(buildMessageBody(resetUrl, token));
            mailSender.send(message);
        } catch (RuntimeException ex) {
            throw new BadRequestException("Unable to send password reset email at the moment");
        }
    }

    private String buildResetUrl(String token) {
        String encodedToken = URLEncoder.encode(token, StandardCharsets.UTF_8);
        return emailProperties.resetBaseUrl() + "?token=" + encodedToken;
    }

    private String buildMessageBody(String resetUrl, String token) {
        return "You requested a password reset for your AuthSphere account.\n\n"
            + "Use this link to set a new password:\n"
            + resetUrl
            + "\n\n"
            + "Or enter this OTP token manually in the reset screen:\n"
            + token
            + "\n\n"
            + "If you did not request this change, you can ignore this email.";
    }

}
