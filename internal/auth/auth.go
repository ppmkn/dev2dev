package auth

import (
	"fmt"
    "time"
	"strings"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"

	"github.com/ppmkn/dev2dev/internal/middleware"
)

var (
    AccessLifeTime = 1 * time.Minute
    //RefreshLifeTime = 30 * 24 * time.Hour
    RefreshLifeTime = 3 * time.Minute
)

func uuidToString(u uuid.UUID) string {
    return u.String()
}

// UserIdExtractor парсит claims и возвращает ID пользователя
func UserIdExtractor(w http.ResponseWriter, r *http.Request) (string, error) {
    // Получаем access токен из заголовка Authorization
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        http.Error(w, "Missing authorization header", http.StatusUnauthorized)
        fmt.Println("Missing authorization header")
        return "", fmt.Errorf("missing authorization header")
    }

    // Формат должен быть "Bearer <access_token>"
    parts := strings.Split(authHeader, " ")
    if len(parts) != 2 || parts[0] != "Bearer" {
        http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
        fmt.Println("Invalid authorization header format")
        return "", fmt.Errorf("invalid authorization header format")
    }

    accessToken := parts[1] // Извлекаем access token

    // Парсим токен и получаем claims
    claims := &middleware.Claims{}
    token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
        return middleware.JwtKey, nil
    })

    if err != nil || !token.Valid {
        http.Error(w, "Invalid or expired access token", http.StatusUnauthorized)
        fmt.Println("Invalid or expired access token:", err)
        return "", fmt.Errorf("invalid or expired access token: %v", err)
    }

    // Извлекаем userID из claims и преобразуем в строку
    userID := uuidToString(claims.UserID)

    return userID, nil
}

// AccessTokenExtractor возвращает access-token пользователя с проверкой на валидность
func AccessTokenExtractor(w http.ResponseWriter, r *http.Request) (string, error) {
    // Получаем access токен из заголовка Authorization
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        http.Error(w, "Missing authorization header", http.StatusUnauthorized)
        fmt.Println("Missing authorization header")
        return "", fmt.Errorf("missing authorization header")
    }

    // Формат должен быть "Bearer <access_token>"
    parts := strings.Split(authHeader, " ")
    if len(parts) != 2 || parts[0] != "Bearer" {
        http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
        fmt.Println("Invalid authorization header format")
        return "", fmt.Errorf("invalid authorization header format")
    }

    accessToken := parts[1] // Извлекаем access token

    // Парсим токен и получаем claims
    claims := &middleware.Claims{}
    token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
        return middleware.JwtKey, nil
    })

    if err != nil || !token.Valid {
        http.Error(w, "Invalid or expired access token", http.StatusUnauthorized)
        fmt.Println("Invalid or expired access token:", err)
        return "", fmt.Errorf("invalid or expired access token: %v", err)
    }

    return accessToken, nil
}