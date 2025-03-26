package lutronbroker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func getWithToken(o *OAuthToken, u string) ([]byte, error) {
	if o.TokenType != "Bearer" {
		return nil, fmt.Errorf("unsupported OAuth token type: %s", o.TokenType)
	}
	client := http.Client{}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+o.AccessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func postJSON[T any](o *OAuthToken, u string, body any, response *T) error {
	if o.TokenType != "Bearer" {
		return fmt.Errorf("unsupported OAuth token type: %s", o.TokenType)
	}
	client := http.Client{}
	bodyData, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", u, bytes.NewReader(bodyData))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+o.AccessToken)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(respData, response)
}
