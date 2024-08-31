package providers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	simplejson "github.com/bitly/go-simplejson"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	yaml "gopkg.in/yaml.v2"
)

var (
	errKeyFileNotSet            = errors.New("key file not set")
	errDecodePublicKey          = errors.New("public key decode error")
	errMissingCode              = errors.New("missing code")
	errNotEstablishedSession    = errors.New("session not established")
	errNeedReEstablishedSession = errors.New("session need to be re-established")
)

const (
	passportProviderName = "Passport"
)

var _ Provider = (*PassportProvider)(nil)

type authConfiguration map[string][]string

// PassportProvider of auth
type PassportProvider struct {
	*ProviderData
	userGroups sync.Map
	auth       authConfiguration
	publicKey  *rsa.PublicKey
}

// NewPassportProvider creates passport provider
func NewPassportProvider(p *ProviderData) (*PassportProvider, error) {
	p.ProviderName = passportProviderName
	provider := &PassportProvider{ProviderData: p}
	if err := provider.loadKey(); err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	if err := provider.LoadAllowed(); err != nil {
		return nil, fmt.Errorf("failed to load allowed: %w", err)
	}

	return provider, nil
}

func (p *PassportProvider) loadKey() error {
	passportKey := os.Getenv("PASSPORT_KEY")
	if passportKey == "" {
		return errKeyFileNotSet
	}

	b, err := os.ReadFile(passportKey)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return errDecodePublicKey
	}

	pubkeyinterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	p.publicKey = pubkeyinterface.(*rsa.PublicKey)

	return nil
}

func (p *PassportProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errMissingCode
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	token := []byte(p.ClientID + ":" + p.ClientSecret)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString(token)))

	resp, err := p.apiRequest(req)
	if err != nil {
		return nil, err
	}

	accessToken, err := resp.Get("access_token").String()
	s = &sessions.SessionState{
		AccessToken: accessToken,
	}

	return
}

func (p *PassportProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	email := ""

	token, err := jwt.Parse(s.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return p.publicKey, nil
	})

	if err == nil && token.Valid {
		login := strings.ToLower(token.Claims.(jwt.MapClaims)["sub"].(string))
		loginParts := strings.Split(login, "\\")
		if len(loginParts) > 1 {
			email = loginParts[1] + "@" + loginParts[0]
			groups, err := p.getUserGroups(token.Raw)
			if err != nil {
				log.Printf("Failed to get %s groups: %s", email, err.Error())
			}
			p.userGroups.Store(email, groups)
		} else {
			email = fmt.Sprintf("%s@local", loginParts[0])
			p.userGroups.Store(email, []string{"local"})
		}
	}

	return email, err
}

func (p *PassportProvider) apiRequest(req *http.Request) (*simplejson.Json, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	var body []byte
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return nil, err
	}

	data, err := simplejson.NewJson(body)
	if err != nil {
		return nil, err
	}

	return data, nil

}

func (p *PassportProvider) getUserGroups(token string) ([]string, error) {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)

	req, err := http.NewRequest("GET", p.ProfileURL.String(), bytes.NewBufferString(params.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	if err != nil {
		log.Printf("failed building request %s", err.Error())
		return nil, err
	}

	json, err := p.apiRequest(req)
	if err != nil {
		log.Printf("failed making request %s", err.Error())
		return nil, err
	}

	groupJson := json.Get("group")
	groups, err := groupJson.String()
	if err == nil {
		return strings.Split(groups, ","), nil
	}

	return groupJson.StringArray()
}

// ValidateRequest validates that the request fits configured provider
// authorization groups
func (p *PassportProvider) ValidateRequest(req *http.Request, s *sessions.SessionState) (bool, error) {
	if s == nil {
		return false, errNotEstablishedSession
	}

	uri := strings.Split(req.Host, ":")[0] + req.URL.Path
	allowedGroups := p.getAllowedGroups(uri)
	_, exAll := allowedGroups["*"]
	if exAll {
		return true, nil
	}

	groups, isKnownUser := p.userGroups.Load(s.Email)
	if !isKnownUser {
		return false, errNeedReEstablishedSession
	}

	for _, group := range groups.([]string) {
		val, ex := allowedGroups[group]
		if ex && val {
			return true, nil
		}
	}

	return false, nil
}

// GetLoginURL with typical oauth parameters
func (p *PassportProvider) GetLoginURL(redirectURI, state, _ string, extraParams url.Values) string {
	a := makeLoginURL(p.ProviderData, redirectURI, state, extraParams)
	return a.String()
}

func (p *PassportProvider) LoadAllowed() error {
	auth := os.Getenv("AUTH_FILE")
	yamlFile, err := os.ReadFile(auth)
	if err != nil {
		return fmt.Errorf("failed to read auth file: %w", err)
	}

	return yaml.Unmarshal(yamlFile, &p.auth)
}

func (p *PassportProvider) getAllowedGroups(uri string) map[string]bool {
	bestMatch := ""
	for key := range p.auth {
		if strings.HasPrefix(uri, key) {
			if len(bestMatch) < len(key) {
				bestMatch = key
			}
		}
	}

	groups, ex := p.auth[bestMatch]
	res := make(map[string]bool)
	if ex {
		for _, group := range groups {
			res[group] = true
		}
	}

	return res
}
