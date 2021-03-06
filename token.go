package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Token struct {
	Config  *TokenConfig
	Payload map[string]interface{}
}

// New allows you to create a token based upon the configuration
// you provide.
func New(c *TokenConfig) *Token {
	return &Token{Config: c, Payload: make(map[string]interface{})}
}

// Set is a convenience method for setting properties within the
// custom claim `payload`. This is where you may store some values
// such as permissions or other metadata
func (t *Token) Set(key string, value interface{}) {
	t.Payload[key] = value
}

// String is a method used for converting the Token
// into an encoded (and possibly signed) string for transmissino
func (t *Token) String(key *rsa.PrivateKey) (string, error) {

	headers := map[string]string{
		"typ": "jwt",
		// Default to no algorithm (i.e. no signature)
		"alg": "none",
	}

	claims := make(map[string]interface{})

	// Run through the provided configuration and add
	// whatever properties have been provided. Most of these
	// are *optional* according to the RFC.
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
		inputHash := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", headerEncoded, claimsEncoded)))
		signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, inputHash[:])
		if err != nil {
			return "", err
		}
		signature = base64.StdEncoding.EncodeToString(signatureBytes)
	}

	return fmt.Sprintf("%s.%s.%s", headerEncoded, claimsEncoded, signature), nil
}

// Parse will take a JWT is string format and return the claims
// and token configuration while automatically processing any claims
// that are found on the token (e.g. `exp`, `nbf`)
func Parse(token string, key *rsa.PublicKey) (*Token, error) {
	if strings.Count(token, ".") != 2 {
		return nil, errors.New("malformed token")
	}

	parts := strings.Split(token, ".")

	if key != nil {
		inputHash := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", parts[0], parts[1])))
		signature, _ := base64.StdEncoding.DecodeString(parts[2])
		err := rsa.VerifyPKCS1v15(key, crypto.SHA256, inputHash[:], signature)
		if err != nil {
			return nil, errors.New("token signature verification failed")
		}
	}

	headerBytes, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	claimsBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var headers map[string]interface{}
	var claims map[string]interface{}

	err = json.Unmarshal(headerBytes, &headers)
	if err != nil {
		return nil, errors.New("token contains invalid JSON")
	}

	err = json.Unmarshal(claimsBytes, &claims)
	if err != nil {
		return nil, errors.New("token contains invalid JSON")
	}

	if claims["exp"] != nil {
		// Hack around Unix epoch being unmarshaled as a float
		claims["exp"] = int32(claims["exp"].(float64))
		if claims["exp"].(int32) < int32(time.Now().Unix()) {
			return nil, errors.New("token has expired")
		}
	}

	output := &Token{Payload: claims["payload"].(map[string]interface{})}
	return output, nil
}

type TokenConfig struct {
	Issuer     string
	Subject    string
	Audience   string
	Expiration int32
	NotBefore  int32
	IssuedAt   int32
}

// DefaultConfig provides a minimal working claims setup
// with a 12-hour token expiration
func DefaultConfig() *TokenConfig {
	return &TokenConfig{
		Expiration: int32(time.Now().Unix()) + (12 * 60 * 60),
	}
}
