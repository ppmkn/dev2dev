package main

import (
    "fmt"
    "log"
    "net/http"
    "os"

    "github.com/gorilla/mux"
    "github.com/joho/godotenv"
    "github.com/ppmkn/dev2dev/internal/api/v1"
    "github.com/ppmkn/dev2dev/internal/database"
)

func main() {
    if err := godotenv.Load("development.env"); err != nil {
        log.Fatalf("Ошибка при загрузке .env файла: %s", err.Error())
    }

	// Инициализация базы данных
    database.ConnectDB()
    defer func() {
        if err := database.GetDB().Close(); err != nil {
            log.Fatalf("Ошибка при закрытии базы данных: %v", err)
        }
    }()

    port := os.Getenv("PORT")

    r := mux.NewRouter()
    v1.RegisterRoutes(r)

    fmt.Println(`
      _           ___     _            
     | |         |__ \   | |           
   __| | _____   __ ) |__| | _____   __
  / _  |/ _ \ \ / // // _  |/ _ \ \ / /
 | (_| |  __/\ V // /| (_| |  __/\ V / 
  \____|\___| \_/|____\____|\___| \_/  
        `)

    log.Println("Запуск сервера на порту: " + port)
    if err := http.ListenAndServe(":"+port, r); err != nil {
        log.Fatal(err)
    }
}