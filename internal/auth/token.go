package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	SecretKey     []byte
	AdminUsername string
	AdminPassword string
}

func GenerateToken(streamName string, expireDuration time.Duration, cfg Config) string {
	expireAt := time.Now().Add(expireDuration).Unix()
	payload := fmt.Sprintf("%s.%d", streamName, expireAt)

	h := hmac.New(sha256.New, cfg.SecretKey)
	h.Write([]byte(payload))

	signature := hex.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s.%s", payload, signature)
}

func VerifyToken(token string, cfg Config) (streamName string, valid bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}

	streamName = parts[0]
	expireAt, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", false
	}

	givenSign := parts[2]

	payload := fmt.Sprintf("%s.%d", streamName, expireAt)

	h := hmac.New(sha256.New, cfg.SecretKey)
	h.Write([]byte(payload))
	expectSign := hex.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(givenSign), []byte(expectSign)) {
		return "", false
	}

	if time.Now().Unix() > expireAt {
		return "", false
	}

	return streamName, true
}
