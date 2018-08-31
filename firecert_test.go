package main

import (
	"fmt"
	"testing"
	// "github.com/stretchr/testify/assert"
	"net"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/stretchr/testify/assert"
	// "log"
)

func getToken(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Authorization", "mitoken")
}

func parseToken(w http.ResponseWriter, req *http.Request) {
	token, _ := request.ParseFromRequest(req, request.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})

	fmt.Println(token)
}

var l net.Listener

func init() {
	http.HandleFunc("/token", parseToken)
	l, _ = net.Listen("tcp", fmt.Sprintf(":%d", 5432))
}

func prepareRequest(r *http.Request) {
	r.Header.Set("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYmYiOjE0NDQ0Nzg0MDB9.0Hq3ieEWEB6Hxs42T0LNm_yJE9mjEq0AVnkO_9b5QGo")
}

func TestFirecert(t *testing.T) {
	// go http.Serve(l, nil)
	// client := &http.Client{}
	// r, _ := http.NewRequest("GET", "http://localhost:5432/token", nil)
	// prepareRequest(r)
	// client.Do(r)
	// r, _ = http.NewRequest("GET", "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com", nil)
	// resp, e := client.Do(r)
	// fmt.Println(resp)
	// fmt.Println(e)
	// l.Close()
	assert.Equal(t, 1, 2, "asd")
}
