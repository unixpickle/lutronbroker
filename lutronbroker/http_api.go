package lutronbroker

import (
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
