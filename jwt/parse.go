package jwt

import (
	"firecert/keys"
	"fmt"
	"net/http"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
)

func Parse(ts string) (*jwtgo.Token, error) {
	return jwtgo.Parse(ts, getKey)
}

func ParseFromRequest(req *http.Request) (*jwtgo.Token, error) {
	return request.ParseFromRequest(req, request.AuthorizationHeaderExtractor, getKey)
}

func getKey(t *jwtgo.Token) (interface{}, error) {
	if _, ok := t.Method.(*jwtgo.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
	}
	kid, ok := t.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid kid: %v", kid)
	}
	key, err := keys.Get(kid)
	if err != nil {
		return nil, err
	}
	return key.PublicKey, nil
}
