package lutronbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func getWithToken(ctx context.Context, o *OAuthToken, u string) ([]byte, error) {
	if o.TokenType != "Bearer" {
		return nil, fmt.Errorf("unsupported OAuth token type: %s", o.TokenType)
	}
	client := http.Client{}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
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

func sendJSON[T any](ctx context.Context, o *OAuthToken, method, u string, body any, response *T) error {
	if o.TokenType != "Bearer" {
		return fmt.Errorf("unsupported OAuth token type: %s", o.TokenType)
	}
	client := http.Client{}
	bodyData, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(bodyData))
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
