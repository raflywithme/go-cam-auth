package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"cam-auth/internal/auth"
)

func TestLoginHandler(t *testing.T) {
	cfg := auth.Config{
		SecretKey:     []byte("secret-ecek-ecek"),
		AdminUsername: "admin",
		AdminPassword: "rahasia123",
	}

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "rahasia123")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	LoginHandler(cfg)(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("EXPECTED REDIRECT STATUS %d, got %d", http.StatusSeeOther, rec.Code)
	}
	if rec.Header().Get("Location") != "/dashboard" {
		t.Errorf("EXPECTED REDIRECT TO /dashboard, GOT '%s'", rec.Header().Get("Location"))
	}

	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "session_id" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Error("EXPECTED session_id COOKIE TO BE SET AFTER SUCCESSFUL LOGIN")
	}
}

func TestLoginHandlerWrongPassword(t *testing.T) {
	cfg := auth.Config{
		SecretKey:     []byte("secret-ecek-ecek"),
		AdminUsername: "admin",
		AdminPassword: "rahasia123",
	}

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "salah")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	LoginHandler(cfg)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("EXPECTED STATUS %d, GOT %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestRootHandlerRedirectsToLoginWhenNoSession(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	RootHandler(rec, req)

	if rec.Header().Get("Location") != "/login" {
		t.Errorf("EXPECTED REDIRECT TO /login, GOT '%s'", rec.Header().Get("Location"))
	}
}

func TestRootHandlerRedirectsToDashboardWhenSessionValid(t *testing.T) {
	sessionID := auth.CreateSession("admin")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID})
	rec := httptest.NewRecorder()
	RootHandler(rec, req)

	if rec.Header().Get("Location") != "/dashboard" {
		t.Errorf("EXPECTED REDIRECT TO /dashboard, GOT '%s'", rec.Header().Get("Location"))
	}
}
