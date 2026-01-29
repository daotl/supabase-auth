package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
	"golang.org/x/oauth2"
)

type genericProvider struct {
	*oauth2.Config
	requiresPKCE    bool
	issuer          string
	profileURL      string
	userDataMapping map[string]string
}

func (p genericProvider) GetOAuthToken(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.Exchange(ctx, code, opts...)
}

func (p genericProvider) RequiresPKCE() bool {
	return p.requiresPKCE
}

func (p genericProvider) GetUserData(_ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u map[string]interface{}

	// Perform http request manually, because we need to vary it based on the provider config
	req, err := http.NewRequest("GET", p.profileURL, nil)
	if err != nil {
		return nil, err
	}

	// set headers
	req.Header.Set("Client-Id", p.ClientID)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer utilities.SafeClose(resp.Body)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("a %v error occurred with retrieving user from OAuth2 provider", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &u)
	if err != nil {
		return nil, err
	}

	// Read user data as specified in the JSON mapping
	mapping := p.userDataMapping

	email, err := getStringFieldByPath(u, mapping["Email"], "")
	if err != nil {
		return nil, err
	}

	emailVerified, err := getBooleanFieldByPath(u, mapping["EmailVerified"], email != "")
	if err != nil {
		return nil, err
	}

	emailPrimary, err := getBooleanFieldByPath(u, mapping["EmailPrimary"], email != "")
	if err != nil {
		return nil, err
	}

	issuer, err := getStringFieldByPath(u, mapping["Issuer"], p.issuer)
	if err != nil {
		return nil, err
	}

	subject, err := getStringFieldByPath(u, mapping["Subject"], "")
	if err != nil {
		return nil, err
	}

	name, err := getStringFieldByPath(u, mapping["Name"], "")
	if err != nil {
		return nil, err
	}

	familyName, err := getStringFieldByPath(u, mapping["FamilyName"], "")
	if err != nil {
		return nil, err
	}

	givenName, err := getStringFieldByPath(u, mapping["GivenName"], "")
	if err != nil {
		return nil, err
	}

	middleName, err := getStringFieldByPath(u, mapping["MiddleName"], "")
	if err != nil {
		return nil, err
	}

	nickName, err := getStringFieldByPath(u, mapping["NickName"], "")
	if err != nil {
		return nil, err
	}

	preferredUsername, err := getStringFieldByPath(u, mapping["PreferredUsername"], "")
	if err != nil {
		return nil, err
	}

	profile, err := getStringFieldByPath(u, mapping["Profile"], "")
	if err != nil {
		return nil, err
	}

	picture, err := getStringFieldByPath(u, mapping["Picture"], "")
	if err != nil {
		return nil, err
	}

	website, err := getStringFieldByPath(u, mapping["Website"], "")
	if err != nil {
		return nil, err
	}

	gender, err := getStringFieldByPath(u, mapping["Gender"], "")
	if err != nil {
		return nil, err
	}

	birthdate, err := getStringFieldByPath(u, mapping["Birthdate"], "")
	if err != nil {
		return nil, err
	}

	zoneInfo, err := getStringFieldByPath(u, mapping["ZoneInfo"], "")
	if err != nil {
		return nil, err
	}

	locale, err := getStringFieldByPath(u, mapping["Locale"], "")
	if err != nil {
		return nil, err
	}

	updatedAt, err := getStringFieldByPath(u, mapping["UpdatedAt"], "")
	if err != nil {
		return nil, err
	}

	phone, err := getStringFieldByPath(u, mapping["Phone"], "")
	if err != nil {
		return nil, err
	}

	phoneVerified, err := getBooleanFieldByPath(u, mapping["PhoneVerified"], phone != "")
	if err != nil {
		return nil, err
	}

	data := &UserProvidedData{
		Emails: []Email{
			{
				Email:    email,
				Verified: emailVerified,
				Primary:  emailPrimary,
			},
		},
		Metadata: &Claims{
			Issuer:            issuer,
			Subject:           subject,
			Name:              name,
			FamilyName:        familyName,
			GivenName:         givenName,
			MiddleName:        middleName,
			NickName:          nickName,
			PreferredUsername: preferredUsername,
			Profile:           profile,
			Picture:           picture,
			Website:           website,
			Gender:            gender,
			Birthdate:         birthdate,
			ZoneInfo:          zoneInfo,
			Locale:            locale,
			UpdatedAt:         updatedAt,
			Email:             email,
			EmailVerified:     emailVerified,
			Phone:             phone,
			PhoneVerified:     phoneVerified,
			// Backward compatibility fields
			ProviderId: subject,
			FullName:   name,
			AvatarURL:  picture,
		},
	}

	return data, nil
}

func getFieldByPath(obj map[string]interface{}, path string, fallback interface{}) (interface{}, error) {
	value := obj

	pathParts := strings.Split(path, ".")
	for index, field := range pathParts {
		fieldValue, ok := value[field]
		if !ok {
			return fallback, nil
		}

		if index == len(pathParts)-1 {
			return fieldValue, nil
		}

		value = fieldValue.(map[string]interface{})
	}

	return nil, nil
}

func getStringFieldByPath(obj map[string]interface{}, path string, fallback string) (string, error) {
	value, err := getFieldByPath(obj, path, fallback)
	if err != nil {
		return "", err
	}
	if result, ok := value.(string); ok {
		return result, nil
	} else if intValue, ok := value.(int); ok {
		return strconv.Itoa(intValue), nil
	} else if floatValue, ok := value.(float64); ok {
		return strconv.Itoa(int(math.Round(floatValue))), nil
	} else if value == nil {
		return "", nil
	} else {
		return "", fmt.Errorf("unable to read field as string: %q %q", path, value)
	}
}

func getBooleanFieldByPath(obj map[string]interface{}, path string, fallback bool) (bool, error) {
	value, err := getFieldByPath(obj, path, fallback)
	if err != nil {
		return false, err
	}
	if result, ok := value.(bool); ok {
		return result, nil
	} else {
		return false, fmt.Errorf("unable to read field as boolean: %q", path)
	}
}

// OIDCDiscovery represents the OIDC Discovery document
// https://openid.net/specs/openid-connect-discovery-1_0.html
type OIDCDiscovery struct {
	Issuer                            string `json:"issuer"`
	AuthorizationEndpoint             string `json:"authorization_endpoint"`
	TokenEndpoint                     string `json:"token_endpoint"`
	UserinfoEndpoint                  string `json:"userinfo_endpoint"`
	JWKSURI                           string `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
}

// NewGenericProvider creates an OAuth provider according to the config specified by the user.
// If DiscoveryURL is set, it will fetch the OIDC Discovery document to obtain the
// authorization_endpoint, token_endpoint, and userinfo_endpoint.
func NewGenericProvider(ext conf.GenericOAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	// Determine auth URL, token URL, and profile URL
	var authURL, tokenURL, profileURL, issuer string

	if ext.DiscoveryURL != "" {
		// Fetch OIDC Discovery document
		discovery, err := fetchOIDCDiscovery(ext.DiscoveryURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
		}

		// Use discovered values
		authURL = discovery.AuthorizationEndpoint
		tokenURL = discovery.TokenEndpoint
		profileURL = discovery.UserinfoEndpoint
		issuer = discovery.Issuer

		// Validate required endpoints
		if authURL == "" {
			return nil, errors.New("discovery document missing authorization_endpoint")
		}
		if tokenURL == "" {
			return nil, errors.New("discovery document missing token_endpoint")
		}
	} else {
		// Use explicitly configured URLs
		if ext.AuthURL == "" {
			return nil, errors.New("missing auth_url (or set discovery_url for OIDC discovery)")
		}
		if ext.TokenURL == "" {
			return nil, errors.New("missing token_url (or set discovery_url for OIDC discovery)")
		}
		authURL = ext.AuthURL
		tokenURL = ext.TokenURL
		profileURL = ext.ProfileURL
		issuer = ext.Issuer
	}

	oauthScopes := strings.Split(scopes, ",")

	return &genericProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		requiresPKCE:    ext.RequiresPKCE,
		issuer:          issuer,
		profileURL:      profileURL,
		userDataMapping: ext.UserDataMapping,
	}, nil
}

// fetchOIDCDiscovery fetches the OIDC Discovery document from the given URL
func fetchOIDCDiscovery(discoveryURL string) (*OIDCDiscovery, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	var discovery OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, err
	}

	return &discovery, nil
}
