package v1

import (
	"encoding/json"
	//"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/ppmkn/dev2dev/internal/database"
	"github.com/ppmkn/dev2dev/internal/middleware"
	"github.com/ppmkn/dev2dev/internal/auth"
	"github.com/ppmkn/dev2dev/internal/utils"
)

type User struct {
	ID       uuid.UUID `json:"id"`
	Nickname string    `json:"nickname"`
	Email    string    `json:"email"`
	Password string    `json:"password"`
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello")
}

func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDB()

	var user User
	json.NewDecoder(r.Body).Decode(&user)

	// Генерация UUID
	user.ID = uuid.New()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Генерация случайного ника
	user.Nickname = utils.GenerateName()

	query := "INSERT INTO users (id, nickname, email, password) VALUES ($1, $2, $3, $4)"
	_, err = db.Exec(query, user.ID, user.Nickname, user.Email, hashedPassword)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "User created successfully")
}

func SignInHandler(w http.ResponseWriter, r *http.Request) {
	// Проверка наличия токена в заголовке Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Проверяем, является ли токен действительным
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &middleware.Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return middleware.JwtKey, nil
		})
		if err == nil && token.Valid {
			// Если токен действителен, возвращаем статус 200 OK и сообщение о том, что пользователь уже авторизован
			http.Error(w, "User already logged in", http.StatusOK)
			return
		}
		// Если токен не действителен, продолжаем обработку аутентификации как обычно
	}

	db := database.GetDB()

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	var storedHash string
	var userID uuid.UUID
	query := "SELECT id, password FROM users WHERE email = $1"
	err := db.QueryRow(query, user.Email).Scan(&userID, &storedHash)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(user.Password))
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(auth.AccessLifeTime)
	claims := &middleware.Claims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	accessTokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(middleware.JwtKey)
	if err != nil {
		http.Error(w, "Could not create access token", http.StatusInternalServerError)
		return
	}

	refreshToken := uuid.New().String() // генерируем новый refresh token
	refreshExpirationTime := time.Now().Add(auth.RefreshLifeTime)

	// Получаем информацию о device из запроса
	deviceInfo := r.UserAgent()

	_, err = db.Exec("INSERT INTO refresh_tokens (user_id, token, expires_at, device_info) VALUES ($1, $2, $3, $4)", userID, refreshToken, refreshExpirationTime, deviceInfo)
	if err != nil {
		fmt.Println("Error saving refresh token:", err)
		http.Error(w, "Could not save refresh token", http.StatusInternalServerError)
		return
	}

	// Отдаём токены в JSON ответе
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessTokenString,
		"refresh_token": refreshToken,
	})
}

func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDB()

	var tokens struct {
		RefreshToken string `json:"refresh_token"`
	}
	json.NewDecoder(r.Body).Decode(&tokens)

	var userID uuid.UUID
	// Проверяем наличие refresh токена
	query := "SELECT user_id FROM refresh_tokens WHERE token = $1"
	err := db.QueryRow(query, tokens.RefreshToken).Scan(&userID)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

    // Извлекаем access-токен из заголовка
    oldAccessToken, err := auth.AccessTokenExtractor(w, r)
    if err != nil {
        fmt.Println("Error extracting access token:", err)
        return
    }

    // Заносим старый access токен в черный список
    _, err = db.Exec("INSERT INTO token_blacklist (token) VALUES ($1)", oldAccessToken)
    if err != nil {
        http.Error(w, "Failed to blacklist access token", http.StatusInternalServerError)
        fmt.Println("Error blacklisting access token:", err)
        return
    }

	// Генерация нового access token
	expirationTime := time.Now().Add(auth.AccessLifeTime)
	claims := &middleware.Claims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	accessTokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(middleware.JwtKey)
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	// Генерация нового refresh token
	newRefreshToken := uuid.New().String()                       // Генерация нового UUID для refresh token
	refreshExpirationTime := time.Now().Add(auth.RefreshLifeTime) // Устанавливаем срок действия для нового refresh token

	// Обновляем/добавляем новый refresh token в базу данных
	_, err = db.Exec("UPDATE refresh_tokens SET token = $1, expires_at = $2 WHERE user_id = $3", newRefreshToken, refreshExpirationTime, userID)
	if err != nil {
		http.Error(w, "Failed to update refresh token", http.StatusInternalServerError)
		return
	}

	// Отправляем новый access token и refresh token клиенту
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessTokenString,
		"refresh_token": newRefreshToken,
	})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDB()

    // Извлекаем access-токен из заголовка
    accessToken, err := auth.AccessTokenExtractor(w, r)
    if err != nil {
        fmt.Println("Error extracting access token:", err)
        return
    }

    // Извлекаем userID из claims
    authUserID, err := auth.UserIdExtractor(w, r)
    if err != nil {
        fmt.Println("Error extracting claims:", err)
        return
    }

	// Удаляем refresh токен из базы данных
	res, err := db.Exec("DELETE FROM refresh_tokens WHERE user_id = $1", authUserID)
	if err != nil {
		http.Error(w, "Failed to log out", http.StatusInternalServerError)
		fmt.Println("Error deleting refresh token:", err)
		return
	}

	affectedRows, _ := res.RowsAffected()
	if affectedRows == 0 {
		fmt.Println("No refresh token found in the database.")
	} else {
		fmt.Println("Refresh token deleted successfully!")
	}

	// Заносим access токен в черный список
	_, err = db.Exec("INSERT INTO token_blacklist (token) VALUES ($1)", accessToken)
	if err != nil {
		http.Error(w, "Failed to blacklist access token", http.StatusInternalServerError)
		fmt.Println("Error blacklisting access token:", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Logged out successfully")
}

// Защищенный обработчик
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "This is a protected route") // Доступ только для авторизованных пользователей
}

// Просмотр своего профиля
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDB()

    // Тут в отличии от UsersHandler
    // мы используем ID из токена, а не из URL

    // Извлекаем userID из claims
    authUserID, err := auth.UserIdExtractor(w, r)
    if err != nil {
        fmt.Println("Error extracting claims:", err)
        return
    }

	// Проверяем существует ли пользователь с таким ID
	var nicknameUser string
	query := "SELECT nickname FROM users WHERE id = $1"
	err = db.QueryRow(query, authUserID).Scan(&nicknameUser)
	if err != nil {
		http.Error(w, "User not found!", http.StatusNotFound)
		return
	}

    // Достаем аватарку
    // var avatar []byte
    // queryTwo := "SELECT avatar FROM user_profiles WHERE user_id = $1"
    // err = db.QueryRow(queryTwo, authUserID).Scan(&avatar)
    // if err != nil {
    //     http.Error(w, "Avatar not found!", http.StatusNotFound)
    //     return
    // }

	// Кодируем аватарку в Base64
	//avatarBase64 := base64.StdEncoding.EncodeToString(avatar)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Nickname string `json:"nickname"` // Анонимная структура с ответом
		//Avatar	 string	`json:"avatar"`
	}{
		Nickname: nicknameUser,
		//Avatar: avatarBase64,
	})
}

// Просмотр профиля пользователя по ID
func UsersHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDB()

	// Достаем ID из URL
	vars := mux.Vars(r)
	userID := vars["id"]

    // Проверяем существует ли пользователь с таким ID
	var nicknameUser string
	query := "SELECT nickname FROM users WHERE id = $1"
	err := db.QueryRow(query, userID).Scan(&nicknameUser)
	if err != nil {
		http.Error(w, "User not found!", http.StatusNotFound)
		return
	}

    // Извлекаем userID из claims
    authUserID, err := auth.UserIdExtractor(w, r)
    if err != nil {
        fmt.Println("Error extracting claims:", err)
        return
    }

	if userID == authUserID {
		// Если это наш профиль
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	} else {
		// Если профиль другого пользователя
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			Nickname string `json:"nickname"` // Анонимная структура с ответом
		}{
			Nickname: nicknameUser,
		})
	}
}

// Загрузка аватарки пользователя
// func AvatarUploadHandler(w http.ResponseWriter, r *http.Request) {
// 	db := database.GetDB()

// 	// Получаем файл из формы
// 	file, _, err := r.FormFile("avatar")
// 	if err != nil {
// 		http.Error(w, "Unable to get file", http.StatusBadRequest)
// 		return
// 	}
// 	defer file.Close()

// 	// Чтение содержимого файла
// 	data, err := io.ReadAll(file)
// 	if err != nil {
// 		http.Error(w, "Unable to read file", http.StatusInternalServerError)
// 		return
// 	}

// 	userID, _ := auth.UserIdExtractor(w, r)

// 	fmt.Printf("File data: %x\n", data[:10]) // Выводим первые 10 байт файла

// 	query := "INSERT INTO user_profiles (user_id, avatar) VALUES ($1, $2)"
// 	_, err = db.Exec(query, userID, data)
// 	if err != nil {
// 		fmt.Println(err.Error())
// 		http.Error(w, "Failed to upload avatar", http.StatusInternalServerError)
// 		return
// 	}

// 	w.Header().Set("Content-Type", "multipart/form-data")
// 	w.WriteHeader(http.StatusOK)
// 	fmt.Fprintln(w, "Image uploaded successfully")
// }