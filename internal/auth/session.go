package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

type Session struct {
	Username 	string
	Expire		time.Time
}

var sessions		= make(map[string]Session)
var sessionsMutex 	sync.Mutex

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func CreateSession(username string) string {
	sessionId := generateSessionID()

	sessionsMutex.Lock()
	sessions[sessionId] = Session{
		Username: username,
		Expire: time.Now().Add(24 * time.Hour),
	}
	sessionsMutex.Unlock()

	return sessionId
}

func GetSession(req *http.Request) (Session, bool){
	cookie, err := req.Cookie("session_id")

	if err != nil {
		return Session{}, false
	}

	sessionsMutex.Lock()
	session, exists := sessions[cookie.Value]
	sessionsMutex.Unlock()

	if !exists {
		return Session{}, false
	}

	if time.Now().After(session.Expire){
		return Session{}, false
	}

	return session, true
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		_, valid := GetSession(req)
		if !valid {
			http.Redirect(res, req, "/login", http.StatusSeeOther)
			return
		}

		next(res, req)
	}
}