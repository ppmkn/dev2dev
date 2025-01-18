package middleware

import (
    "os"
    "log"
    "net/http"
    "strings"
    "time"

    "github.com/joho/godotenv"
    "github.com/dgrijalva/jwt-go"
    "github.com/google/uuid"
    "github.com/ppmkn/dev2dev/internal/database"
)

// Загрузка переменных окружения из .env файла
func init() {
    err := godotenv.Load("development.env")
    if err != nil {
        log.Fatalf("Ошибка при загрузке .env файла: %v", err)
    }
}

// Ключ для подписи JWT, теперь извлекаем из переменной окружения
var JwtKey = []byte(os.Getenv("JWT_KEY"))

// Структура claims для JWT
type Claims struct {
    UserID uuid.UUID `json:"user_id"`
    jwt.StandardClaims
}

func TokenAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Получаем токен из заголовка Authorization
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Missing authorization header", http.StatusUnauthorized)
            return
        }

        // Формат должен быть "Bearer <token>"
        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
            return
        }

        tokenString := parts[1]

        claims := &Claims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return JwtKey, nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
            return
        }

        // Проверяем, не в черном списке ли токен
        db := database.GetDB()

        var exists bool
        row := db.QueryRow("SELECT EXISTS(SELECT 1 FROM token_blacklist WHERE token=$1)", tokenString)
        row.Scan(&exists)
        if exists {
            http.Error(w, "Token is blacklisted", http.StatusUnauthorized)
            return
        }

        // Проверка срока действия токена
        if time.Unix(claims.ExpiresAt, 0).Before(time.Now()) {
            http.Error(w, "Token has expired", http.StatusUnauthorized)
            return
        }

        // Передаем управление следующему обработчику
        next.ServeHTTP(w, r)
    }
}

// Функция для очистки черного списка токенов
func CleanTokenBlacklist() {
    db := database.GetDB()

    // Задаем период, например, 1 дней
    retentionPeriod := 1 * 24 * time.Hour
    thresholdDate := time.Now().Add(-retentionPeriod)

    // Удаляем токены, которые были заблокированы более 1 дня назад
    _, err := db.Exec("DELETE FROM token_blacklist WHERE revoked_at < $1", thresholdDate)
    if err != nil {
        // Логируем ошибку, если это необходимо
        log.Println("Error cleaning token blacklist:", err)
    }
}