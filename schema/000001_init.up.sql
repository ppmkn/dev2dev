  CREATE EXTENSION IF NOT EXISTS "pgcrypto";

  CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),    -- Ранее BIGSERIAL
    nickname VARCHAR(32) NOT NULL,
    email TEXT NOT NULL UNIQUE,                        -- Email должен быть уникальным
    password TEXT NOT NULL                           -- Пароль требуется
  --email_confirmed BOOLEAN DEFAULT FALSE             -- Флаг для подтверждения email
  );

  CREATE TABLE user_profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    bio TEXT,
    avatar BYTEA,
    --avatar_url TEXT,
    birthdate DATE
  );

  ----------------------------------------------------------------------------

  CREATE TABLE refresh_tokens (
      id SERIAL PRIMARY KEY,
      user_id UUID NOT NULL,
      token TEXT NOT NULL UNIQUE,
      device_info TEXT NOT NULL, -- информация о устройстве
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE token_blacklist (
      id SERIAL PRIMARY KEY,
      token TEXT NOT NULL UNIQUE,
      revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );