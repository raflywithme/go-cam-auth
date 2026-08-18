package handler

import (
	"net/http"
	"time"

	"cam-auth/internal/auth"
)

func LoginHandler(cfg auth.Config) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		if req.Method == "GET" {
			http.ServeFile(res, req, "web/page/login.html")
			return
		}

		if req.Method == "POST" {
			username := req.FormValue("username")
			password := req.FormValue("password")

			if username == cfg.AdminUsername && password == cfg.AdminPassword {
				sessionId := auth.CreateSession(username)

				http.SetCookie(res, &http.Cookie{
					Name:     "session_id",
					Value:    sessionId,
					Path:     "/",
					HttpOnly: true,
					Expires:  time.Now().Add(24 * time.Hour),
				})

				http.Redirect(res, req, "/dashboard", http.StatusSeeOther)
				return
			}

			http.Error(res, "WRONG USERNAME OR PASSWORD", http.StatusUnauthorized)
			return
		}

		http.Error(res, "METHOD NOT ALLOWED", http.StatusMethodNotAllowed)
	}
}

func RootHandler(res http.ResponseWriter, req *http.Request) {
	_, valid := auth.GetSession(req)
	if valid {
		http.Redirect(res, req, "/dashboard", http.StatusSeeOther)
		return
	}

	http.Redirect(res, req, "/login", http.StatusSeeOther)
}
