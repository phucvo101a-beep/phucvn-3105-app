-- Schema Addon for 3105 API v2 Security
-- Anti-Replay Nonce Cache & Multi-Device Hardening

CREATE TABLE IF NOT EXISTS `api_nonces` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `nonce_hex` VARCHAR(64) NOT NULL UNIQUE,
    `created_at` INT UNSIGNED NOT NULL,
    INDEX `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Clean up expired nonces automatically (can be run via cron)
-- DELETE FROM `api_nonces` WHERE `created_at` < (UNIX_TIMESTAMP() - 600);
