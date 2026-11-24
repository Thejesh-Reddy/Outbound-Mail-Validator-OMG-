-- For a NEW, EMPTY database only. Do not DROP existing production tables.
CREATE DATABASE IF NOT EXISTS OMG_Database CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE OMG_Database;
CREATE TABLE IF NOT EXISTS users (
  id CHAR(24) NOT NULL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(320) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS auth_sessions (
  id CHAR(24) NOT NULL PRIMARY KEY,
  account_id CHAR(24) NOT NULL,
  jti_hash CHAR(64) NOT NULL UNIQUE,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  revoked_at DATETIME NULL,
  INDEX idx_account_id (account_id),
  INDEX idx_expires_at (expires_at),
  CONSTRAINT fk_auth_account FOREIGN KEY (account_id) REFERENCES users(id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS email_analysis (
  id CHAR(24) NOT NULL PRIMARY KEY,
  transaction_id CHAR(36) NOT NULL UNIQUE,
  status ENUM('SAFE','WARNING','RESTRICTED') NOT NULL,
  confidence_score DECIMAL(5,2) NOT NULL,
  message VARCHAR(100) NOT NULL,
  text_result JSON NULL,
  url_result JSON NULL,
  attachment_result JSON NULL,
  error_details JSON NULL,
  popup JSON NULL
) ENGINE=InnoDB;
