package k

import (
	"time"
)

const (
	DefaultCacheTime = 1 * time.Hour
	GoogleKeysURL    = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
	Alg              = "RS256"
	GoogleIssURL     = "https://securetoken.google.com/"
)

func CompareIssUrl(url, iss string) bool {
	return url == GoogleIssURL+iss
}
