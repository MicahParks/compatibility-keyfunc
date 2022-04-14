package keyfunc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
	f3t "github.com/form3tech-oss/jwt-go"
)

var (
	// ErrKID indicates that the JWT had an invalid kid.
	ErrKID = errors.New("the JWT has an invalid kid")
)

// KeyfuncLegacy is a compatibility function that matches the signature of github.com/dgrijalva/jwt-go's jwt.Keyfunc
// function.
func (j *JWKS) KeyfuncLegacy(token *jwt.Token) (interface{}, error) {
	kidInter, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("%w: could not find kid in JWT header", ErrKID)
	}
	kid, ok := kidInter.(string)
	if !ok {
		return nil, fmt.Errorf("%w: could not convert kid in JWT header to string", ErrKID)
	}

	return j.getKey(kid)
}

// KeyfuncF3T is a compatibility function that matches the signature of github.com/form3tech-oss/jwt-go's Keyfunc
// function.
func (j *JWKS) KeyfuncF3T(f3tToken *f3t.Token) (interface{}, error) {
	token := &jwt.Token{
		Raw:       f3tToken.Raw,
		Method:    f3tToken.Method,
		Header:    f3tToken.Header,
		Claims:    f3tToken.Claims,
		Signature: f3tToken.Signature,
		Valid:     f3tToken.Valid,
	}
	return j.KeyfuncLegacy(token)
}

// base64urlTrailingPadding removes trailing padding before decoding a string from base64url. Some non-RFC compliant
// JWKS contain padding at the end values for base64url encoded public keys.
//
// Trailing padding is required to be removed from base64url encoded keys.
// RFC 7517 defines base64url the same as RFC 7515 Section 2:
// https://datatracker.ietf.org/doc/html/rfc7517#section-1.1
// https://datatracker.ietf.org/doc/html/rfc7515#section-2
func base64urlTrailingPadding(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}
