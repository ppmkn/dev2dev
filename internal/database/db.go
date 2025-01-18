package database

import (
	"os"
	"fmt"
    "log"
    "database/sql"

    _ "github.com/lib/pq"
    "github.com/joho/godotenv"
)

var db *sql.DB

func ConnectDB() *sql.DB {
    // Проверка: если уже есть соединение, то возвращаем его
    if db != nil {
        return db
    }

    // Загружаем переменные .env
    err := godotenv.Load("development.env")
    if err != nil {
        log.Fatalf("Ошибка при загрузке .env файла: %v", err)
    }

    dbUser := os.Getenv("DB_USER")
    dbPassword := os.Getenv("DB_PASSWORD")
    dbHost := os.Getenv("DB_HOST")
    dbName := os.Getenv("DB_NAME")
    dbSSLMode := os.Getenv("DB_SSLMODE")

    // Формируем строку подключения
    connStr := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=%s",
        dbHost, dbUser, dbPassword, dbName, dbSSLMode)

    db, err = sql.Open("postgres", connStr)
    if err != nil {
        log.Fatalf("Ошибка при подключении к базе данных: %v", err)
    }

    if err := db.Ping(); err != nil {
        log.Fatalf("Не удалось пингануть базу данных: %v", err)
    }

    log.Println("Успешно подключено к базе данных!")
    return db
}

// GetDB возвращает экземпляр БД
func GetDB() *sql.DB {
    if db == nil {
		panic("База данных не инициализирована!")
	}
	return db
}