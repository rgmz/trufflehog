package aws

import (
	"sync"

	regexp "github.com/wasilibs/go-re2"
)

const (
	RequiredIdEntropy     = 3.0
	RequiredSecretEntropy = 4.25
)

var SecretPat = regexp.MustCompile(`(?:[^A-Za-z0-9+/]|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\z)`)

type IdentityResponse struct {
	GetCallerIdentityResponse struct {
		GetCallerIdentityResult struct {
			Account string `json:"Account"`
			Arn     string `json:"Arn"`
			UserID  string `json:"UserId"`
		} `json:"GetCallerIdentityResult"`
		ResponseMetadata struct {
			RequestID string `json:"RequestId"`
		} `json:"ResponseMetadata"`
	} `json:"GetCallerIdentityResponse"`
}

type Error struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

type ErrorResponseBody struct {
	Error Error `json:"Error"`
}

type KeyMutex struct {
	m sync.Map
}

func (km *KeyMutex) getMutex(key string) *sync.Mutex {
	val, _ := km.m.LoadOrStore(key, &sync.Mutex{})
	return val.(*sync.Mutex)
}

func (km *KeyMutex) Do(key string, call func() (bool, map[string]string, error)) (bool, map[string]string, error) {
	mu := km.getMutex(key)
	mu.Lock()
	defer mu.Unlock()
	return call()
}
