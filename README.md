# JSON Web Tokens for Go

[![Build Status](https://travis-ci.org/mattkrea/go-jwt.svg?branch=master)](https://travis-ci.org/mattkrea/go-jwt)
[![GoDoc](https://godoc.org/github.com/mattkrea/go-jwt?status.svg)](https://godoc.org/github.com/mattkrea/go-jwt)

# Basic Usage

## Creating a Token

```go
// Create a token
token := jwt.New(jwt.DefaultConfig)

// Add an `email` property to the claims payload
token.Set("email", "user@domain.com")

// Get the encoded string version of the token
encodedToken := token.String(nil)

// Alternatively, you can get an RSA signed copy of the
// token. By default tokens are unsigned in the package.
key, _ := rsa.GenerateKey(rand.Reader, 2048)
signedToken := token.String(key)
```

## Parsing and Validating

To validate, simply follow the examples below. You will get nearly an exact recreation of the original token you had created *however* `err` will be non-nil if the token expired or if `claims.nbf` is in the future.

```go
// without a key
result, err := jwt.Parse(token, nil)

// with a public key
result, err := jwt.Parse(token, key)
```

# Advanced Usage

By default tokens are not signed nor do they include many optional claims. In many cases, though, these claims are quite useful so via `TokenConfig` you may set whichever you like. For more information regarding these claims see [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4).


```go

// Set up your token claims
config := &jwt.TokenConfig{
	Issuer: "My Company",
	Subject: "Leeroy Jenkins",
	Audience: "Sales Agent",
	// Must wait 30 minutes before the token is considered valid
	NotBefore: int32(time.Now().Unix()) + (30 * 60)
	Expiration: int32(time.Now().Unix()) + (12 * 60 * 60),
}

token := jwt.New(config)

// Add an `email` property to the claims payload
token.Set("email", "user@domain.com")

// Get the encoded string version of the token
encodedToken := token.String(nil)
```