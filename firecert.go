package main

import (
	"firecert/jwt"
	"firecert/k"
	"firecert/keys"
	"net/http"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
)

type Firecert struct {
	*jwtgo.Token
	ProjectID string
}

func New(projID string) Firecert {
	fc := Firecert{}
	fc.ProjectID = projID
	return fc
}

func (fc *Firecert) Parse(ts string) error {
	t, err := jwt.Parse(ts)
	if err != nil {
		return err
	}
	fc.Token = t
	return nil
}

func (fc *Firecert) ParseFromRequest(req *http.Request) error {
	t, err := jwt.ParseFromRequest(req)
	if err != nil {
		return err
	}
	fc.Token = t
	return nil
}

func (fc *Firecert) Verify() bool {
	if found := keys.Exists(fc.Token.Header["kid"].(string)); found && fc.Token.Header["alg"] == "RS256" {
		if claims, ok := fc.Token.Claims.(jwtgo.MapClaims); ok && fc.Token.Valid {
			now := float64(time.Now().Unix())
			if claims["exp"].(float64) > now && claims["iat"].(float64) < now {
				if claims["aud"] == fc.ProjectID && k.CompareIssUrl(claims["iss"].(string), fc.ProjectID) {
					return true
				}
			}
		}
	}
	return false
}

func main() {
	fc := New("test-7699b")
	fc.Parse("eyJhbGciOiJSUzI1NiIsImtpZCI6IjNiYzVhOTIwYjk2NjRlMTQ1Y2I2ZDZkMGY2ODhhZGM2ODk1MmRjNWIifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vdGVzdC03Njk5YiIsImF1ZCI6InRlc3QtNzY5OWIiLCJhdXRoX3RpbWUiOjE0OTA4MjU3NDksInVzZXJfaWQiOiJzUDBvUHpsbVQ2V2tUNmRaQ3VMa1hYamRtR2kyIiwic3ViIjoic1Awb1B6bG1UNldrVDZkWkN1TGtYWGpkbUdpMiIsImlhdCI6MTQ5MDgzMDY2OSwiZXhwIjoxNDkwODM0MjY5LCJlbWFpbCI6ImFndWZpdWJhQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZmlyZWJhc2UiOnsiaWRlbnRpdGllcyI6eyJlbWFpbCI6WyJhZ3VmaXViYUBnbWFpbC5jb20iXX0sInNpZ25faW5fcHJvdmlkZXIiOiJwYXNzd29yZCJ9fQ.h7zmQ76WkRmGD6nI3QUY36cQd18DQ0KxF9GCU3tzDSKBCaBTGQ6For3oMjQ9FMa-pqdFiwsA9ZkpC1HYR3PcNBtKZ8SN1v1htqyNxbPIUL_2Gb3tyOZTJcxUbzRYndbkml_e_vUOOM_5M2WXQY2LpoP9zzVDy3p1h9JBBM2YS0-NRP17s3szx3NOi3m3bbTRmtwvdrl3DiSbL3PcLZpMdzHjpNStIShzHxwxb2K4jhGqG_6fIeQu0zV-7WXtEcU-mhdYvJtREpZ_19Ci3nupP73gD_XjUA0wjnALwuSpLpj1B3eDQshXvGqidJ103G_Ve9vdHQZ-ViH-s5A_YdDPAg")
}
