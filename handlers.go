package main

import (
	"database/sql"
	"html/template"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)
 
var tmpl = template.Must(template.ParseGlob("templates/*.html"))
var secretKey = []byte("secret_key")
var (
    todos []*Todo
    mutex sync.Mutex
)
func homeHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Получение username из JWT
        cookie, err := r.Cookie("jwt")
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        claims := jwt.MapClaims{}
        _, err = jwt.ParseWithClaims(cookie.Value, claims, func(t *jwt.Token) (interface{}, error) {
            return secretKey, nil
        })
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        // Получение задач из БД
        var userID int
        err = db.QueryRow("SELECT id FROM users WHERE username = $1", claims["user_name"]).Scan(&userID)
        if err != nil {
            http.Error(w, "User not found", http.StatusBadRequest)
            return
        }

        todos, err := getTodos(db, userID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Передача данных в шаблон
        data := struct {
            Username string
            Todos    []Todo
        }{
            Username: claims["user_name"].(string),
            Todos:    todos,
        }

        tmpl.ExecuteTemplate(w, "home.html", data)
    }
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

// Обработчик переключения статуса задачи
func toggleHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }

        // Получаем ID пользователя из JWT
        cookie, err := r.Cookie("jwt")
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        claims := jwt.MapClaims{}
        _, err = jwt.ParseWithClaims(cookie.Value, claims, func(t *jwt.Token) (interface{}, error) {
            return secretKey, nil
        })
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        var userID int
        err = db.QueryRow("SELECT id FROM users WHERE username = $1", claims["user_name"]).Scan(&userID)
        if err != nil {
            http.Error(w, "User not found", http.StatusBadRequest)
            return
        }

        // Получаем ID задачи из формы
        todoID, err := strconv.Atoi(r.FormValue("id"))
        if err != nil {
            http.Error(w, "Invalid task ID", http.StatusBadRequest)
            return
        }

        // Обновляем статус задачи в базе (только если она принадлежит пользователю)
        _, err = db.Exec(`
            UPDATE todos 
            SET completed = NOT completed 
            WHERE id = $1 AND user_id = $2`,
            todoID, userID,
        )
        if err != nil {
            http.Error(w, "Failed to update task", http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/home", http.StatusFound)
    }
}

// Обработчик удаления задачи
func deleteHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }

        // Получаем ID пользователя из JWT
        cookie, err := r.Cookie("jwt")
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        claims := jwt.MapClaims{}
        _, err = jwt.ParseWithClaims(cookie.Value, claims, func(t *jwt.Token) (interface{}, error) {
            return secretKey, nil
        })
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        var userID int
        err = db.QueryRow("SELECT id FROM users WHERE username = $1", claims["user_name"]).Scan(&userID)
        if err != nil {
            http.Error(w, "User not found", http.StatusBadRequest)
            return
        }

        // Получаем ID задачи из формы
        todoID, err := strconv.Atoi(r.FormValue("id"))
        if err != nil {
            http.Error(w, "Invalid task ID", http.StatusBadRequest)
            return
        }

        // Удаляем задачу из базы (только если она принадлежит пользователю)
        _, err = db.Exec(`
            DELETE FROM todos 
            WHERE id = $1 AND user_id = $2`,
            todoID, userID,
        )
        if err != nil {
            http.Error(w, "Failed to delete task", http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/home", http.StatusFound)
    }
}


func addHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Получение user_id из JWT
        cookie, _ := r.Cookie("jwt")
        claims := jwt.MapClaims{}
        jwt.ParseWithClaims(cookie.Value, claims, func(t *jwt.Token) (interface{}, error) { return secretKey, nil })
        
        var userID int
        err := db.QueryRow("SELECT id FROM users WHERE username = $1", claims["user_name"]).Scan(&userID)
        if err != nil {
            http.Error(w, "User not found", http.StatusBadRequest)
            return
        }

        text := r.FormValue("text")
        _, err = db.Exec("INSERT INTO todos(user_id, text) VALUES($1, $2)", userID, text)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        http.Redirect(w, r, "/home", http.StatusFound)
    }
}

// Получение задач для пользователя
func getTodos(db *sql.DB, userID int) ([]Todo, error) {
    rows, err := db.Query("SELECT id, text, completed FROM todos WHERE user_id = $1", userID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var todos []Todo
    for rows.Next() {
        var t Todo
        err := rows.Scan(&t.ID, &t.Text, &t.Completed)
        if err != nil {
            return nil, err
        }
        todos = append(todos, t)
    }
    return todos, nil
}
