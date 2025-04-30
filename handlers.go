package main

import (
	"database/sql"
	"html/template"
	"net/http"
	"time"
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v5"
)
 
var tmpl = template.Must(template.ParseGlob("templates/*.html"))
var secretKey = []byte("secret_key")
func homeHandler(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("jwt")
	if err != nil {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    tokenString := cookie.Value
    claims := jwt.MapClaims{}
    jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return secretKey, nil
    })
    
    tmpl.ExecuteTemplate(w, "home.html", map[string]interface{}{
        "Username": claims["user_name"],
    })
}

func loginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			tmpl.ExecuteTemplate(w, "login.html", nil)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		var user User
		err := db.QueryRow("SELECT id, username, password_hash FROM users WHERE username = $1", username).
			Scan(&user.ID, &user.Username, &user.Password)
		if err != nil {
			if err == sql.ErrNoRows {
				tmpl.ExecuteTemplate(w, "login.html", "Invalid username or password")
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			tmpl.ExecuteTemplate(w, "login.html", "Invalid username or password")
			return
		}

		token, err := generateToken(username)
		if err != nil {
			tmpl.ExecuteTemplate(w, "login.html", "Error")
			return
		}

		_, err = db.Exec("UPDATE users SET jwtkey = $1 WHERE username = $2", token, username)
		if err != nil {
    		http.Error(w, err.Error(), http.StatusInternalServerError)
   			 return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "jwt",
			Value:    token,
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
			Path:     "/",
		})
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
}
func generateToken(Username string) (string, error) {
    claims := jwt.MapClaims{
        "user_name": Username,
        "exp":     time.Now().Add(time.Hour * 24).Unix(), // срок 24 часа
    }
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(secretKey)
}
func logoutHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// удаляю куки
		http.SetCookie(w, &http.Cookie{
			Name:     "jwt",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HttpOnly: true,
			Path:     "/",
		})

		// очищаю жвт токен в бд
		cookie, _ := r.Cookie("jwt")
		if cookie != nil {
			tokenString := cookie.Value
			claims := jwt.MapClaims{}
			token, _ := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return secretKey, nil
			})
			if token != nil && token.Valid {
				username := claims["user_name"].(string)
				db.Exec("UPDATE users SET jwtkey = NULL WHERE username = $1", username)
			}
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}
func registerHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			tmpl.ExecuteTemplate(w, "register.html", nil)
			return
		}

		Username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = db.Exec(
			"INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
			Username, email, string(hashedPassword),
		)
		if err != nil {
			tmpl.ExecuteTemplate(w, "register.html", "Username or email already exists")
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

