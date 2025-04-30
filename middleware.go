package main

import (
	"database/sql"
	"net/http"
	"github.com/golang-jwt/jwt/v5"
)
func authMiddleware(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// получаем токен из кукии
			cookie, err := r.Cookie("jwt")
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			tokenString := cookie.Value
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return secretKey, nil
			})

			if err != nil || !token.Valid {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			
			// проверка токена в постгрес
			claims := token.Claims.(jwt.MapClaims)
			username := claims["user_name"].(string)
			
			var storedToken string
			err = db.QueryRow("SELECT jwtkey FROM users WHERE username = $1", username).Scan(&storedToken)
			if err != nil || storedToken == "" || storedToken != tokenString {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
func redirectIfAuth(db *sql.DB) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            cookie, err := r.Cookie("jwt")
            if err != nil {
                next.ServeHTTP(w, r)
                return
            }

            token, err := jwt.Parse(cookie.Value, func(t *jwt.Token) (interface{}, error) {
                return secretKey, nil
            })

            if err != nil || !token.Valid {
                next.ServeHTTP(w, r)
                return
            }

            // проверка токена в пострес
            claims := token.Claims.(jwt.MapClaims)
            username := claims["user_name"].(string)
            
            var storedToken string
            err = db.QueryRow("SELECT jwtkey FROM users WHERE username = $1", username).Scan(&storedToken)
            if err == nil && storedToken == cookie.Value {
                http.Redirect(w, r, "/home", http.StatusFound)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}