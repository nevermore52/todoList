package main

import (
	"net/http"
	"github.com/gorilla/mux"
)

func main() {
	db := initDB()
	defer db.Close()

	r := mux.NewRouter()
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	r.Handle("/login", redirectIfAuth(db)(loginHandler(db))).Methods("GET", "POST")
	r.Handle("/register", redirectIfAuth(db)(registerHandler(db))).Methods("GET", "POST")
	r.Handle("/logout", logoutHandler(db))

	// Protected routes
	protected := r.PathPrefix("").Subrouter()
	protected.Use(authMiddleware(db))
	protected.HandleFunc("/home", homeHandler)
	protected.HandleFunc("/", homeHandler)

	http.ListenAndServe(":8080", r)
}