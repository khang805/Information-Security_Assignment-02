CREATE DATABASE IF NOT EXISTS securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'securechat_user'@'%' IDENTIFIED BY 'replace_me';
GRANT ALL PRIVILEGES ON securechat.* TO 'securechat_user'@'%';
FLUSH PRIVILEGES;

USE securechat;

CREATE TABLE IF NOT EXISTS users (
  email VARCHAR(255) NOT NULL,
  username VARCHAR(64) NOT NULL UNIQUE,
  salt VARBINARY(16) NOT NULL,
  pwd_hash CHAR(64) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (username)
);

