CREATE TABLE user_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    refresh_token_jti VARCHAR(64) NOT NULL UNIQUE,
    refresh_token_hash VARCHAR(128) NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    revoke_reason VARCHAR(64),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_revoked_at ON user_sessions(revoked_at);

