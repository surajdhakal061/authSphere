ALTER TABLE user_sessions ADD COLUMN device_name VARCHAR(120);
ALTER TABLE user_sessions ADD COLUMN ip_address VARCHAR(64);
ALTER TABLE user_sessions ADD COLUMN user_agent VARCHAR(255);
ALTER TABLE user_sessions ADD COLUMN last_seen_at TIMESTAMP;

UPDATE user_sessions
SET last_seen_at = issued_at,
    device_name = 'unknown-device',
    ip_address = 'unknown',
    user_agent = 'unknown'
WHERE last_seen_at IS NULL;

ALTER TABLE user_sessions ALTER COLUMN last_seen_at SET NOT NULL;

