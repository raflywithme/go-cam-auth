package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCreateAndGetValidSession(t *testing.T) {
	sessionId := CreateSession("testing")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionId})

	session, valid := GetSession(req)

	if !valid {
		t.Fatal("EXPECT VALID SESSION, GOT INVALID")
	}

	if session.Username != "testing" {
		t.Errorf("EXPECTED USERNAME 'testing', GOT '%s'", session.Username)
	}
}

func TestGetSessionNoCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, valid := GetSession(req)

	if valid {
		t.Fatal("EXPECTED NO SESSION, GOT VALID")
	}
}

func TestGetSessionInvalidCookieValue(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "apacoba"})

	_, valid := GetSession(req)

	if valid {
		t.Fatal("EXPECTED INVALID SESSION, GOT VALID")
	}
}

func TestGetSessionExpired(t *testing.T) {
	sessionId := "expired-test"
	sessionsMutex.Lock()
	sessions[sessionId] = Session{
		Username: "testing",
		Expire:   time.Now().Add(-1 * time.Hour),
	}
	sessionsMutex.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionId})

	_, valid := GetSession(req)

	if valid {
		t.Fatal("EXPECTED EXPIRED, GOT VALID")
	}
}

func TestAuthMiddlewareRedirectsNoSession(t *testing.T) {
	called := false
	handler := AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if called {
		t.Error("EXPECTED HANDLER NOT CALLED WHEN NO SESSION")
	}

	if rec.Code != http.StatusSeeOther {
		t.Errorf("EXPECTED REDIRECT STATUS %d, GOT %d", http.StatusSeeOther, rec.Code)
	}

	if rec.Header().Get("Location") != "/login" {
		t.Errorf("EXPECTED REDIRECT TO /login, GOT %s", rec.Header().Get("Location"))
	}
}

func TestAuthMiddlewareRedirectsWithValidSession(t *testing.T) {
	sessionId := CreateSession("testing")

	called := false
	handler := AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionId})
	rec := httptest.NewRecorder()
	handler(rec, req)

	if !called {
		t.Error("EXPECTED HANDLER TO BE CALLED")
	}
}
