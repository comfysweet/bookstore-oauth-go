package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/comfysweet/bookstore-oauth-go/oauth/errors"
	"github.com/mercadolibre/golang-restclient/rest"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http:localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(r *http.Request) bool {
	if r == nil {
		return true
	}
	return r.Header.Get(headerXPublic) == "true"
}

func GetCallerId(r *http.Request) int64 {
	if r == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(r.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(r *http.Request) int64 {
	if r == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(r.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(r *http.Request) *errors.RestErr {
	if r == nil {
		return nil
	}

	clearRequest(r)
	accessTokenId := strings.TrimSpace(r.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	accessToken, err := getAccessToken(accessTokenId)
	if err != nil {
		return err
	}

	r.Header.Add(headerXClientId, fmt.Sprintf("%v", accessToken.ClientId))
	r.Header.Add(headerXCallerId, fmt.Sprintf("%v", accessToken.UserId))

	return nil
}

func clearRequest(r *http.Request) {
	if r == nil {
		return
	}
	r.Header.Del(headerXClientId)
	r.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("oauth/access_token/%s", accessTokenId))
	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServiceError("invalid rest client response when trying to get access token")
	}
	if response.StatusCode > 299 {
		var restErr errors.RestErr
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, errors.NewInternalServiceError("invalid error interface")
		}
		return nil, &restErr
	}

	var accessToken accessToken
	if err := json.Unmarshal(response.Bytes(), &accessToken); err != nil {
		return nil, errors.NewInternalServiceError("error when unmarshal access token response")
	}
	return &accessToken, nil
}
