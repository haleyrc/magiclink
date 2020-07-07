package magiclink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

type User struct {
	Email         string `json:"email"`
	Issuer        string `json:"issuer"`
	PublicAddress string `json:"public_address"`
}

func GetIssuerFromToken(t string) (string, error) {
	dec, err := base64.StdEncoding.DecodeString(t)
	if err != nil {
		return "", err
	}

	var sections []string
	if err := json.Unmarshal(dec, &sections); err != nil {
		return "", err
	}
	if len(sections) != 2 {
		return "", errors.New("malformed token")
	}

	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal([]byte(sections[1]), &claims); err != nil {
		return "", err
	}

	return claims.Issuer, nil
}

type Client struct {
	APIKey  string
	BaseURL string
}

func (c *Client) GetMetadataFromIssuer(issuer string) (*User, error) {
	u, err := url.Parse(c.BaseURL + "/v1/admin/auth/user/get")
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Set("issuer", issuer)
	u.RawQuery = params.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Magic-Secret-Key", c.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	var responseBody struct {
		User      *User  `json:"data"`
		ErrorCode string `json:"error_code"`
		Message   string `json:"message"`
		Status    string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&responseBody); err != nil {
		return nil, err
	}
	resp.Body.Close()

	if responseBody.Status == "failed" {
		return nil, errors.New(responseBody.Message)
	}

	return responseBody.User, nil
}
