package jwt

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfiguration(t *testing.T) {
	config := DefaultConfig()
	exp := int32(time.Now().Unix()) + (12 * 60 * 60)
	assert.Equal(t, exp, config.Expiration, "should provide 12 hour expiration")
}

func TestNew(t *testing.T) {

	exp := int32(time.Now().Unix()) + (12 * 60 * 60)
	aud := "Merchants"

	config := &TokenConfig{Expiration: exp, Audience: aud}

	token := New(config)

	assert.Equal(t, exp, token.Config.Expiration, "should include provided expiration")
	assert.Equal(t, aud, token.Config.Audience, "should match provided audience")
	assert.Equal(t, "", token.Config.Issuer, "should not include issuer if not provided")
}

func TestSet(t *testing.T) {
	token := New(DefaultConfig())
	assert.Equal(t, nil, token.Payload["age"], "should not start with payload property")
	token.Set("age", 24)
	assert.Equal(t, 24, token.Payload["age"], "should contain `set` prop")
}

func TestString(t *testing.T) {
	token := New(DefaultConfig())
	token.Set("name", "Test")
	output, err := token.String(nil)
	assert.Equal(t, nil, err, "should properly encode token")
	assert.Equal(t, 2, strings.Count(output, "."))
}
