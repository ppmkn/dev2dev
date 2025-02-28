package v1

import (
    "github.com/gorilla/mux"
    "github.com/ppmkn/dev2dev/internal/middleware"
)

func RegisterRoutes(r *mux.Router) {
    r.HandleFunc("/", IndexHandler).Methods("GET")
    //Аутентификация
    r.HandleFunc("/auth/sign-up", SignUpHandler).Methods("POST")
    r.HandleFunc("/auth/sign-in", SignInHandler).Methods("POST")
    r.HandleFunc("/auth/refresh-token", RefreshTokenHandler).Methods("POST")
    r.HandleFunc("/auth/logout", LogoutHandler).Methods("POST")
    //Профили пользователей
    r.HandleFunc("/protected", middleware.TokenAuthMiddleware(ProtectedHandler)).Methods("GET")
    r.HandleFunc("/profile", middleware.TokenAuthMiddleware(ProfileHandler)).Methods("GET")
    r.HandleFunc("/profile/edit", middleware.TokenAuthMiddleware(ProfileEditGetHandler)).Methods("GET")
    r.HandleFunc("/profile/edit", middleware.TokenAuthMiddleware(ProfileEditPostHandler)).Methods("POST")
//  r.HandleFunc("/profile/avatar", middleware.TokenAuthMiddleware(AvatarUploadHandler)).Methods("POST")
    r.HandleFunc("/users/{id}", middleware.TokenAuthMiddleware(UsersHandler)).Methods("GET")
}