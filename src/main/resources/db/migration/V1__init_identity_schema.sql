CREATE TABLE app_users (
    id UUID PRIMARY KEY,
    email VARCHAR(320) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL,
    email_verified BOOLEAN NOT NULL,
    failed_login_count INTEGER NOT NULL,
    locked_until TIMESTAMP,
    token_version INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_app_users_email ON app_users(email);

