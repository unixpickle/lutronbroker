package lutronbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"

	"github.com/unixpickle/essentials"
)

const ()

var (
	ErrNoCSRFToken = errors.New("failed to find csrf token")
	ErrLoginFailed = errors.New("login incorrect")
)

type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	CreatedAt    int64  `json:"created_at"`
}

// GetOAuthToken authenticates the user to derive an OAuth token
// which can be used in future HTTPS requests.
func GetOAuthToken(ctx context.Context, email, password string) (result *OAuthToken, err error) {
	defer essentials.AddCtxTo("get OAuth token", &err)

	code, err := getAuthCode(ctx, email, password)
	if err != nil {
		return nil, err
	}

	client := http.Client{}
	postBody := url.Values{}
	postBody.Add("client_id", signInClientID)
	postBody.Add("client_secret", signInClientSecret)
	postBody.Add("redirect_uri", signInRedirect)
	postBody.Add("grant_type", "authorization_code")
	postBody.Add("code", code)
	postBodyReader := bytes.NewReader([]byte(postBody.Encode()))
	postReq, err := http.NewRequestWithContext(ctx, "POST", signInOAuthURL, postBodyReader)
	if err != nil {
		return nil, err
	}
	postReq.Header.Add("content-type", "application/x-www-form-urlencoded")
	resp, err := client.Do(postReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var response struct {
		OAuthToken
		Err     *string `json:"error"`
		ErrDesc string  `json:"error_description"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	if response.Err != nil {
		return nil, fmt.Errorf("%s: %s", *response.Err, response.ErrDesc)
	}
	return &response.OAuthToken, nil
}

func getAuthCode(ctx context.Context, email, password string) (code string, err error) {
	defer essentials.AddCtxTo("get authentication code", &err)

	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	client := http.Client{Jar: jar}

	query := url.Values{}
	query.Add("client_id", signInClientID)
	query.Add("redirect_uri", signInRedirect)
	query.Add("response_type", "code")
	fullURL := signInBase + "?" + query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	authTokenExpr := regexp.MustCompilePOSIX(`name="authenticity_token" value="([^"]*)"`)
	match := authTokenExpr.FindSubmatch(body)
	if match == nil {
		return "", ErrNoCSRFToken
	}
	csrfToken := string(match[1])

	formURL := resp.Request.URL.String()

	postBody := url.Values{}
	postBody.Add("authenticity_token", csrfToken)
	postBody.Add("user[email]", email)
	postBody.Add("user[password]", password)
	postBody.Add("commit", "Sign In")
	postBodyReader := bytes.NewReader([]byte(postBody.Encode()))
	postReq, err := http.NewRequestWithContext(ctx, "POST", formURL, postBodyReader)
	if err != nil {
		return "", err
	}
	postReq.Header.Add("content-type", "application/x-www-form-urlencoded")
	resp, err = client.Do(postReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	newLocation := resp.Request.URL
	if newLocation.Query().Has("code") {
		s := newLocation.Query().Get("code")
		return s, nil
	}
	return "", ErrLoginFailed
}
