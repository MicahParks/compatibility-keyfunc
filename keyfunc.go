package keyfunc

import (
	"errors"
	"fmt"

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

	// Get the kid from the token header.
	kidInter, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("%w: could not find kid in JWT header", ErrKID)
	}
	kid, ok := kidInter.(string)
	if !ok {
		return nil, fmt.Errorf("%w: could not convert kid in JWT header to string", ErrKID)
	}

	// Get the Go type for the correct cryptographic key.
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
