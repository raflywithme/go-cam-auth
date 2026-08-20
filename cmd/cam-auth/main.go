package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"cam-auth/internal/auth"
	"cam-auth/internal/handler"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Fai	led to load .env: ", err)
	}

	cfg := auth.Config{
		SecretKey:     []byte(os.Getenv("SECRET_KEY")),
		AdminPassword: os.Getenv("ADMIN_PASSWORD"),
		AdminUsername: os.Getenv("ADMIN_USERNAME"),
	}

	http.HandleFunc("/", handler.RootHandler)
	http.HandleFunc("/login", handler.LoginHandler(cfg))
	http.HandleFunc("/dashboard", auth.AuthMiddleware(handler.DashboardHandler))
	http.HandleFunc("/token", auth.AuthMiddleware(handler.TokenHandler(cfg)))
	http.HandleFunc("/verify", handler.VerifyHandler(cfg))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8899"
	}

	fmt.Println("Server running in :" + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
