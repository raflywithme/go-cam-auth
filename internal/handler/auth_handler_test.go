package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cam-auth/internal/auth"
)

func TestTokenHandler(t *testing.T) {
	cfg := auth.Config{
		SecretKey:     []byte("secret-ecek-ecek"),
		AdminUsername: "admin",
		AdminPassword: "rahasia123",
	}

	req := httptest.NewRequest(http.MethodGet, "/token?stream=cam1", nil)
	rec := httptest.NewRecorder()
	TokenHandler(cfg)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("EXPECTED STATUS %d, GOT %d", http.StatusOK, rec.Code)
	}

	body := strings.TrimSpace(rec.Body.String())
	parts := strings.Split(body, ".")
	if len(parts) != 3 {
		t.Errorf("EXPECTED TOKEN WITH 3 PARTS (STREAM.EXPIRE.SIGNATURE), GOT: %s", body)
	}
	if parts[0] != "cam1" {
		t.Errorf("EXPECTED STREAM NAME 'CAM1' IN TOKEN, GOT '%s'", parts[0])
	}
}

func TestTokenHandlerMissingStreamParam(t *testing.T) {
	cfg := auth.Config{
		SecretKey:     []byte("secret-ecek-ecek"),
		AdminUsername: "admin",
		AdminPassword: "rahasia123",
	}

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	rec := httptest.NewRecorder()
	TokenHandler(cfg)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("EXPECTED STATUS %d, GOT %d", http.StatusBadRequest, rec.Code)
	}
}

func TestVerifyHandlerValidToken(t *testing.T) {
	cfg := auth.Config{
		SecretKey:     []byte("secret-ecek-ecek"),
		AdminUsername: "admin",
		AdminPassword: "rahasia123",
	}

	token := auth.GenerateToken("cam1", 1*time.Hour, cfg)

	req := httptest.NewRequest(http.MethodGet, "/verify?token="+token+"&stream=cam1", nil)
	rec := httptest.NewRecorder()
	VerifyHandler(cfg)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("EXPECTED STATUS %d, GOT %d, BODY: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
}

func TestVerifyHandlerWrongStream(t *testing.T) {
	cfg := auth.Config{
		SecretKey:     []byte("secret-ecek-ecek"),
		AdminUsername: "admin",
		AdminPassword: "rahasia123",
	}

	token := auth.GenerateToken("cam1", 1*time.Hour, cfg)

	req := httptest.NewRequest(http.MethodGet, "/verify?token="+token+"&stream=cam2", nil)
	rec := httptest.NewRecorder()
	VerifyHandler(cfg)(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("EXPECTED STATUS %d FOR MISMATCHED STREAM, GOT %d", http.StatusForbidden, rec.Code)
	}
}

func TestVerifyHandler_InvalidToken(t *testing.T) {
	cfg := auth.Config{
		SecretKey:     []byte("secret-ecek-ecek"),
		AdminUsername: "admin",
		AdminPassword: "rahasia123",
	}

	req := httptest.NewRequest(http.MethodGet, "/verify?token=asal-ngarang&stream=cam1", nil)
	rec := httptest.NewRecorder()
	VerifyHandler(cfg)(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("EXPECTED STATUS %d FOR INVALID TOKEN, GOT %d", http.StatusForbidden, rec.Code)
	}
}
