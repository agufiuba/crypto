package keys

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"firecert/k"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	cacheTime time.Time
	lock      sync.RWMutex
	keys      map[string]*x509.Certificate
)

func getCacheTimeFromResponse(resp *http.Response) time.Duration {
	cacheHeader := strings.Split(resp.Header.Get("Cache-Control"), ",")
	for _, c := range cacheHeader {
		c = strings.TrimSpace(c)
		if strings.HasPrefix(c, "max-age=") {
			if d, err := strconv.Atoi(c[len("max-age="):]); err == nil {
				return time.Duration(d) * time.Second
			}
		}
	}
	return k.DefaultCacheTime
}

func download(t http.RoundTripper) (map[string]*x509.Certificate, error) {
	if t == nil {
		t = http.DefaultTransport
	}
	client := http.Client{Transport: t}
	resp, err := client.Get(k.GoogleKeysURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code getting google certificates: ", resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	keys, err = parse(body)
	if err != nil {
		return nil, err
	}
	cacheTime = time.Now().Add(getCacheTimeFromResponse(resp))
	return keys, nil
}

func parse(b []byte) (map[string]*x509.Certificate, error) {
	m := make(map[string]string)
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	keys := make(map[string]*x509.Certificate)
	for k, v := range m {
		block, _ := pem.Decode([]byte(v))
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		keys[k] = c
	}
	return keys, nil
}

func Get(kid string) (*x509.Certificate, error) {
	lock.RLock()
	ct := cacheTime
	lock.RUnlock()
	if ct.Before(time.Now()) {
		var err error
		lock.Lock()
		keys, err = download(nil)
		lock.Unlock()
		if err != nil {
			return nil, err
		}
	}
	key, found := keys[kid]
	if !found {
		return nil, fmt.Errorf("certificate not found for kid: %s", kid)
	}
	return key, nil
}

func Exists(k string) bool {
	lock.Lock()
	_, found := keys[k]
	lock.Unlock()
	return found
}
