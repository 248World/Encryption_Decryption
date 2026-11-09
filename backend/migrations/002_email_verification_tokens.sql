CREATE TABLE email_verification_tokens (
    id CHAR(36) NOT NULL,
    user_id CHAR(36) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_email_verification_tokens_token_hash (token_hash),
    KEY idx_email_verification_tokens_user_expiry (user_id, expires_at),

    CONSTRAINT fk_email_verification_tokens_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE RESTRICT
) ENGINE=InnoDB;