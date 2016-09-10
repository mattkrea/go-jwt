package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type Token struct {
	Config  *TokenConfig
	Payload map[string]interface{}
}

func New(c *TokenConfig) *Token {
	return &Token{Config: c, Payload: make(map[string]interface{})}
}

func (t *Token) Set(key string, value interface{}) {
	t.Payload[key] = value
}

// String is a method used for converting the Token
// into an encoded (and possibly signed) string for transmissino
func (t *Token) String(key *rsa.PrivateKey) (string, error) {

	headers := map[string]string{
		"typ": "jwt",
		// Default to no algorithm
		"alg": "none",
	}

	claims := make(map[string]interface{})

	// Run through the provided configuration and add
	// whatever properties have been provided
	if t.Config.Issuer != "" {
		claims["iss"] = t.Config.Issuer
	}

	if t.Config.Subject != "" {
		claims["sub"] = t.Config.Subject
	}

	if t.Config.Audience != "" {
		claims["aud"] = t.Config.Audience
	}

	if t.Config.Expiration > 0 {
		claims["exp"] = t.Config.Expiration
	}

	if t.Config.NotBefore > 0 {
		claims["nbf"] = t.Config.NotBefore
	}

	if t.Config.IssuedAt > 0 {
		claims["iat"] = t.Config.IssuedAt
	}

	claims["payload"] = t.Payload

	// Check if a key has been passed in. If we have one
	// we will secure the token using `RS256`.
	if key != nil {
		headers["alg"] = "RS256"
	}

	headerBytes, err := json.Marshal(headers)
	if err != nil {
		return "", err
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerEncoded := base64.StdEncoding.EncodeToString(headerBytes)
	claimsEncoded := base64.StdEncoding.EncodeToString(claimsBytes)

	signature := ""
	// If a key was provided let us add a signature to the key that can
	// later be validated with the public key
	if key != nil {

		inputBytes := []byte(fmt.Sprintf("%s.%s", headerEncoded, claimsEncoded))
		hash := sha256.New()
		hash.Write(inputBytes)
		inputHash := hash.Sum(nil)

		signatureBytes, err := key.Sign(rand.Reader, inputHash, crypto.SHA256)
		if err != nil {
			return "", err
		}
		signature = base64.StdEncoding.EncodeToString(signatureBytes)
	}

	return fmt.Sprintf("%s.%s.%s", headerEncoded, claimsEncoded, signature), nil
}

type TokenConfig struct {
	Issuer     string
	Subject    string
	Audience   string
	Expiration int32
	NotBefore  int32
	IssuedAt   int32
}

func DefaultConfig() *TokenConfig {
	return &TokenConfig{
		// Default to 12 hour expiration
		Expiration: int32(time.Now().Unix()) + (12 * 60 * 60),
	}
}
