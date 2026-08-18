package auth

import (
	"testing"
	"time"
)

func testConfig() Config {
	return Config{SecretKey: []byte("secret-ecek-ecek")}
}

func TestGenerateAndVerifyValidToken(t *testing.T) {
	cfg := testConfig()
	token := GenerateToken("cam1", 1*time.Hour, cfg)

	streamName, valid := VerifyToken(token, cfg)

	if !valid {
		t.Fatalf("EXPECTED TOKEN VALID, GOT INVALID. TOKEN: %s", token)
	}
	if streamName != "cam1" {
		t.Errorf("EXPECTED STREAMNAME 'CAM1', GOT '%s'", streamName)
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	cfg := testConfig()
	token := GenerateToken("cam1", -1*time.Hour, cfg)

	_, valid := VerifyToken(token, cfg)

	if valid {
		t.Fatal("EXPECTED TOKEN EXPIRED, BUT GOT VALID")
	}
}

func TestVerifyTamperedSignatureToken(t *testing.T) {
	cfg := testConfig()
	token := GenerateToken("cam1", 1*time.Hour, cfg)
	tampered := token[:len(token)-5] + "aaaaa"

	_, valid := VerifyToken(tampered, cfg)

	if valid {
		t.Fatal("EXPECTED TAMPERED TOKEN TO BE INVALID, BUT GOT VALID")
	}
}

func TestVerifyMalformedFormatToken(t *testing.T) {
	cfg := testConfig()
	cases := []string{
		"",
		"cuma-satu-bagian",
		"dua.bagian",
		"kebanyakan.titik.di.sini.token",
	}

	for _, c := range cases {
		_, valid := VerifyToken(c, cfg)
		if valid {
			t.Errorf("EXPECTED MALFORMED TOKEN '%s' TO BE INVALID, BUT GOT VALID", c)
		}
	}
}
