-- Расширение pgcrypto для генерации UUID
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Установка временной зоны
SET TIMEZONE = 'UTC';

-- Таблица пользователей
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),    -- Ранее BIGSERIAL
    nickname VARCHAR(32) NOT NULL,
    email TEXT NOT NULL UNIQUE,                        -- Email должен быть уникальным
    password TEXT NOT NULL                           -- Пароль требуется
);

-- Таблица профилей пользователей
CREATE TABLE users_profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    bio TEXT,
    avatar BYTEA,
    --avatar_url TEXT,
    birthdate DATE
);

-- Таблица для refresh токенов
CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    token TEXT NOT NULL UNIQUE,
    device_info TEXT NOT NULL, -- информация о устройстве
    expires_at TIMESTAMPTZ NOT NULL, -- timestamp with time zone
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP, -- timestamp with time zone
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Таблица для черного списка токенов
CREATE TABLE token_blacklist (
    id SERIAL PRIMARY KEY,
    token TEXT NOT NULL UNIQUE,
    revoked_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP -- timestamp with time zone
);