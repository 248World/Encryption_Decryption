-- CipherNest SecureShare
-- Migration 001: Initial database schema

USE ciphernest_secureshare;

-- 1. Users
CREATE TABLE users (
    id CHAR(36) PRIMARY KEY,
    email VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    email_verified_at DATETIME NULL,
    account_status ENUM('active', 'suspended', 'disabled')
        NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Business workspaces
CREATE TABLE businesses (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    created_by CHAR(36) NOT NULL,
    status ENUM('active', 'suspended', 'closed')
        NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_business_creator
        FOREIGN KEY (created_by) REFERENCES users(id)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Employee memberships and roles
CREATE TABLE memberships (
    id CHAR(36) PRIMARY KEY,
    business_id CHAR(36) NOT NULL,
    user_id CHAR(36) NOT NULL,
    role ENUM('owner', 'admin', 'employee')
        NOT NULL DEFAULT 'employee',
    status ENUM('active', 'suspended', 'removed')
        NOT NULL DEFAULT 'active',
    joined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uq_business_user (business_id, user_id),
    INDEX idx_membership_user (user_id),

    CONSTRAINT fk_membership_business
        FOREIGN KEY (business_id) REFERENCES businesses(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_membership_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Employee invitations
CREATE TABLE invitations (
    id CHAR(36) PRIMARY KEY,
    business_id CHAR(36) NOT NULL,
    invited_by CHAR(36) NOT NULL,
    email VARCHAR(254) NOT NULL,
    role ENUM('admin', 'employee')
        NOT NULL DEFAULT 'employee',
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    accepted_at DATETIME NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_invitation_email (email),
    INDEX idx_invitation_business (business_id),

    CONSTRAINT fk_invitation_business
        FOREIGN KEY (business_id) REFERENCES businesses(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_invitation_sender
        FOREIGN KEY (invited_by) REFERENCES users(id)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Folders
CREATE TABLE folders (
    id CHAR(36) PRIMARY KEY,
    business_id CHAR(36) NOT NULL,
    parent_folder_id CHAR(36) NULL,
    created_by CHAR(36) NOT NULL,
    encrypted_name LONGBLOB NOT NULL,
    name_iv BINARY(12) NOT NULL,
    name_tag BINARY(16) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_folder_business (business_id),
    INDEX idx_folder_parent (parent_folder_id),

    CONSTRAINT fk_folder_business
        FOREIGN KEY (business_id) REFERENCES businesses(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_folder_parent
        FOREIGN KEY (parent_folder_id) REFERENCES folders(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_folder_creator
        FOREIGN KEY (created_by) REFERENCES users(id)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 6. Encrypted files
CREATE TABLE files (
    id CHAR(36) PRIMARY KEY,
    business_id CHAR(36) NOT NULL,
    folder_id CHAR(36) NULL,
    uploaded_by CHAR(36) NOT NULL,

    -- Private object-storage location, never a public URL
    storage_key VARCHAR(512) NOT NULL UNIQUE,

    -- File content encryption metadata
    encryption_algorithm VARCHAR(40)
        NOT NULL DEFAULT 'AES-256-GCM',
    content_iv BINARY(12) NOT NULL,
    content_tag BINARY(16) NOT NULL,
    encrypted_size BIGINT UNSIGNED NOT NULL,
    original_size BIGINT UNSIGNED NOT NULL,
    ciphertext_sha256 BINARY(32) NOT NULL,

    -- Wrapped data encryption key; never store a plaintext DEK
    wrapped_dek VARBINARY(512) NOT NULL,
    key_wrapping_algorithm VARCHAR(60) NOT NULL,
    kek_version VARCHAR(100) NOT NULL,

    -- Original filename and MIME metadata are encrypted
    encrypted_metadata LONGBLOB NOT NULL,
    metadata_iv BINARY(12) NOT NULL,
    metadata_tag BINARY(16) NOT NULL,

    status ENUM('active', 'quarantined', 'deleted')
        NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_file_business (business_id),
    INDEX idx_file_folder (folder_id),
    INDEX idx_file_uploader (uploaded_by),

    CONSTRAINT fk_file_business
        FOREIGN KEY (business_id) REFERENCES businesses(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_file_folder
        FOREIGN KEY (folder_id) REFERENCES folders(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_file_uploader
        FOREIGN KEY (uploaded_by) REFERENCES users(id)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 7. Secure sharing links
CREATE TABLE shares (
    id CHAR(36) PRIMARY KEY,
    business_id CHAR(36) NOT NULL,
    created_by CHAR(36) NOT NULL,

    file_id CHAR(36) NULL,
    folder_id CHAR(36) NULL,

    -- Store only the hash of the random sharing token
    token_hash CHAR(64) NOT NULL UNIQUE,

    password_hash VARCHAR(255) NULL,
    allow_download BOOLEAN NOT NULL DEFAULT TRUE,

    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,

    max_downloads INT UNSIGNED NULL,
    download_count INT UNSIGNED NOT NULL DEFAULT 0,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_share_business (business_id),
    INDEX idx_share_file (file_id),
    INDEX idx_share_folder (folder_id),
    INDEX idx_share_expiry (expires_at),

    CONSTRAINT chk_share_single_target
        CHECK (
            (file_id IS NOT NULL AND folder_id IS NULL)
            OR
            (file_id IS NULL AND folder_id IS NOT NULL)
        ),

    CONSTRAINT fk_share_business
        FOREIGN KEY (business_id) REFERENCES businesses(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_share_creator
        FOREIGN KEY (created_by) REFERENCES users(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_share_file
        FOREIGN KEY (file_id) REFERENCES files(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_share_folder
        FOREIGN KEY (folder_id) REFERENCES folders(id)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 8. External sharing recipients
CREATE TABLE share_recipients (
    id CHAR(36) PRIMARY KEY,
    share_id CHAR(36) NOT NULL,
    email VARCHAR(254) NOT NULL,

    otp_code_hash VARCHAR(255) NULL,
    otp_expires_at DATETIME NULL,
    otp_attempts INT UNSIGNED NOT NULL DEFAULT 0,
    verified_at DATETIME NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uq_share_recipient (share_id, email),

    CONSTRAINT fk_recipient_share
        FOREIGN KEY (share_id) REFERENCES shares(id)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 9. Login sessions
CREATE TABLE sessions (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_session_user (user_id),
    INDEX idx_session_expiry (expires_at),

    CONSTRAINT fk_session_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 10. Security and audit logs
CREATE TABLE audit_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    business_id CHAR(36) NULL,
    actor_user_id CHAR(36) NULL,

    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(50) NULL,
    target_id CHAR(36) NULL,

    ip_address VARBINARY(16) NULL,
    user_agent VARCHAR(500) NULL,
    details JSON NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_audit_business_time (business_id, created_at),
    INDEX idx_audit_actor_time (actor_user_id, created_at),
    INDEX idx_audit_target (target_type, target_id),

    CONSTRAINT fk_audit_business
        FOREIGN KEY (business_id) REFERENCES businesses(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_audit_actor
        FOREIGN KEY (actor_user_id) REFERENCES users(id)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;