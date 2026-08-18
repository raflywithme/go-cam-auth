package handler

import (
	"fmt"
	"net/http"
	"time"

	"cam-auth/internal/auth"
)

func TokenHandler(cfg auth.Config) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		streamName := req.URL.Query().Get("stream")

		if streamName == "" {
			http.Error(res, "STREAM PARAM REQUIRED", http.StatusBadRequest)
			return
		}

		token := auth.GenerateToken(streamName, 1*time.Hour, cfg)
		fmt.Fprintln(res, token)
	}
}

func VerifyHandler(cfg auth.Config) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		token := req.URL.Query().Get("token")
		requestedStream := req.URL.Query().Get("stream")

		streamName, valid := auth.VerifyToken(token, cfg)

		if !valid {
			http.Error(res, "TOKEN INVALID OR EXPIRED", http.StatusForbidden)
			return
		}

		if streamName != requestedStream {
			http.Error(res, "TOKEN INVALID FOR THIS STREAM", http.StatusForbidden)
			return
		}

		fmt.Fprintln(res, "SUCCESS")
	}
}
