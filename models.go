package main

import (
	"time"
)

type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	JwtKey    string    `json:"jwtkey"`
	CreatedAt time.Time `json:"created_at"`
}

type LoginForm struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterForm struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}