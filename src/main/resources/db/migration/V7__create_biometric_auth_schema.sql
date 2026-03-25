CREATE TABLE biometric_credentials (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    credential_id VARCHAR(128) NOT NULL UNIQUE,
    public_key VARCHAR(512) NOT NULL,
    credential_name VARCHAR(120) NOT NULL,
    sign_count BIGINT NOT NULL,
    last_used_at TIMESTAMP,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_biometric_credentials_user_id FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE CASCADE
);

CREATE INDEX idx_biometric_credentials_user_id ON biometric_credentials(user_id);
CREATE INDEX idx_biometric_credentials_revoked_at ON biometric_credentials(revoked_at);

CREATE TABLE biometric_challenges (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    purpose VARCHAR(32) NOT NULL,
    challenge_value VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    credential_id_hint VARCHAR(128),
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_biometric_challenges_user_id FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE CASCADE
);

CREATE INDEX idx_biometric_challenges_user_id ON biometric_challenges(user_id);
CREATE INDEX idx_biometric_challenges_expires_at ON biometric_challenges(expires_at);

