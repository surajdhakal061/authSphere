package com.suraj.authsphere.auth.service;

import com.suraj.authsphere.auth.config.EmailProperties;
import com.suraj.authsphere.common.exception.BadRequestException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class VerificationEmailService {

    private static final Logger log = LoggerFactory.getLogger(VerificationEmailService.class);

    private final EmailProperties emailProperties;
    private final JavaMailSender mailSender;

    public VerificationEmailService(EmailProperties emailProperties, JavaMailSender mailSenderProvider) {
        this.emailProperties = emailProperties;
        this.mailSender = mailSenderProvider;
    }

    public void sendVerificationEmail(String recipientEmail, String token) {
        String verificationUrl = buildVerificationUrl(token);

        if (!emailProperties.isEnabled()) {
            log.info("Email sending disabled. Verification link for {} -> {}", recipientEmail, verificationUrl);
            return;
        }

        if (mailSender == null) {
            throw new BadRequestException("Email sender is not configured");
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(emailProperties.getFrom());
            message.setTo(recipientEmail);
            message.setSubject("Verify your AuthSphere account");
            message.setText(buildMessageBody(verificationUrl));
            mailSender.send(message);
        } catch (RuntimeException ex) {
            throw new BadRequestException("Unable to send verification email at the moment");
        }
    }

    private String buildVerificationUrl(String token) {
        String encodedToken = URLEncoder.encode(token, StandardCharsets.UTF_8);
        return emailProperties.getVerificationBaseUrl() + "?token=" + encodedToken;
    }

    private String buildMessageBody(String verificationUrl) {
        return "Welcome to AuthSphere!\n\n"
            + "Please verify your email by opening this link:\n"
            + verificationUrl
            + "\n\n"
            + "If you did not create this account, you can ignore this email.";
    }
}

