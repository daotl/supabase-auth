package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
)

func (ts *ExternalTestSuite) TestSignupExternalGeneric() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=generic1", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Generic1.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Generic1.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))

	// Verify state is a valid flow state UUID
	assertValidOAuthState(ts, q.Get("state"), "generic1")

	// Verify flow state was created with correct params in database
	stateUUID := q.Get("state")
	flowState, err := models.FindFlowStateByID(ts.API.db, stateUUID)
	ts.Require().NoError(err)
	ts.Equal("generic1", flowState.ProviderType)
	ts.Equal("oauth", flowState.AuthenticationMethod)
}

func (ts *ExternalTestSuite) TestSignupExternalGenericWithInviteToken() {
	// Create a user with invite token first
	token := "test_invite_token"
	ts.createUser("123", "generic@example.com", "", "", token)

	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=generic1&invite_token="+token, nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)

	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()

	// Verify flow state was created with invite token
	stateUUID := q.Get("state")
	flowState, err := models.FindFlowStateByID(ts.API.db, stateUUID)
	ts.Require().NoError(err)
	ts.Equal("generic1", flowState.ProviderType)
	ts.Equal("oauth", flowState.AuthenticationMethod)
	ts.NotNil(flowState.InviteToken)
	ts.Equal(token, *flowState.InviteToken)
}

func (ts *ExternalTestSuite) TestSignupExternalGenericWithPKCE() {
	// PKCE code challenge must be 43-128 characters
	codeChallenge := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=generic1&code_challenge="+codeChallenge+"&code_challenge_method=S256", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)

	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()

	// Verify flow state was created with PKCE params
	stateUUID := q.Get("state")
	flowState, err := models.FindFlowStateByID(ts.API.db, stateUUID)
	ts.Require().NoError(err)
	ts.Equal("generic1", flowState.ProviderType)
	ts.NotNil(flowState.CodeChallenge)
	ts.Equal("s256", *flowState.CodeChallengeMethod)
}

func (ts *ExternalTestSuite) TestSignupExternalGenericWithOIDCDiscovery() {
	// This test uses the actual DISCOVERY_URL from hack/test.env
	// which should point to a real OIDC discovery endpoint
	discoveryURL := ts.Config.External.Generic1.DiscoveryURL
	if discoveryURL == "" {
		// Skip test when DISCOVERY_URL is not configured (e.g., in CI)
		ts.T().Skip("DISCOVERY_URL not configured - requires external OIDC provider")
		return
	}

	// Test authorization flow - should redirect to discovered auth URL
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=generic1", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)

	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err)
	q := u.Query()

	// Verify redirect is to a valid authorization endpoint (not the mock server)
	ts.NotEqual("http://localhost", u.Scheme+"://"+u.Host)
	ts.Equal("code", q.Get("response_type"))
	ts.NotEmpty(q.Get("state"))

	// The redirect URL should contain client_id from config
	ts.Equal(ts.Config.External.Generic1.ClientID[0], q.Get("client_id"))
}

func GenericTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, emails string) *httptest.Server {
	return GenericTestSignupSetupWithDiscovery(ts, tokenCount, userCount, code, emails, false)
}

func GenericTestSignupSetupWithDiscovery(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, emails string, useDiscovery bool) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Generic1.RedirectURI, r.FormValue("redirect_uri"))
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"generic_token","expires_in":100000}`)
		case "/profile":
			*userCount++
			var emailList []provider.Email
			if err := json.Unmarshal([]byte(emails), &emailList); err != nil {
				ts.Fail("Invalid email json %s", emails)
			}

			var email *provider.Email

			for i, e := range emailList {
				if len(e.Email) > 0 {
					email = &emailList[i]
					break
				}
			}

			if email == nil {
				w.WriteHeader(400)
				return
			}

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprintf(w, `
				{
					"id":123,
					"generic_account": {
						"profile": {
							"nickname":"Generic Test",
							"profile_image_url":"http://example.com/avatar"
						},
						"email": "%v",
						"is_email_valid": %v,
						"is_email_verified": %v
					}
				}`, email.Email, email.Verified, email.Verified)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown generic oauth call %s", r.URL.Path)
		}
	}))

	if !useDiscovery {
		// Use mock server endpoints (clear discovery URL and set explicit URLs)
		ts.Config.External.Generic1.DiscoveryURL = ""
		ts.Config.External.Generic1.AuthURL = server.URL + "/authorize"
		ts.Config.External.Generic1.TokenURL = server.URL + "/token"
		ts.Config.External.Generic1.ProfileURL = server.URL + "/profile"
	}

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalGeneric_AuthorizationCode() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()
	u := performAuthorization(ts, "generic1", code, "")
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "generic@example.com",
		"Generic Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalGenericDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "generic@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalGenericDisableSignupErrorWhenEmptyEmail() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user profile from external provider", "server_error", "generic@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalGenericDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("123", "generic@example.com", "Generic Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "generic@example.com",
		"Generic Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalGenericSuccessWhenMatchingToken() {
	// name and avatar should be populated from external API
	ts.createUser("123", "generic@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "generic@example.com",
		"Generic Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalGenericErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	w := performAuthorizationRequest(ts, "generic1", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalGenericErrorWhenWrongToken() {
	ts.createUser("123", "generic@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	w := performAuthorizationRequest(ts, "generic1", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalGenericErrorWhenEmailDoesntMatch() {
	ts.createUser("123", "generic@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"other@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}

func (ts *ExternalTestSuite) TestSignupExternalGenericErrorWhenVerifiedFalse() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": false}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "")

	v, err := url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.Equal("access_denied", v.Get("error"))
	ts.Equal("provider_email_needs_verification", v.Get("error_code"))
	ts.Equal("Unverified email with generic1. A confirmation email has been sent to your generic1 email", v.Get("error_description"))
}

func (ts *ExternalTestSuite) TestSignupExternalGenericErrorWhenUserBanned() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "")
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "generic@example.com",
		"Generic Test", "123", "http://example.com/avatar")

	user, err := models.FindUserByEmailAndAudience(ts.API.db, "generic@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	t := time.Now().Add(24 * time.Hour)
	user.BannedUntil = &t
	require.NoError(ts.T(), ts.API.db.UpdateOnly(user, "banned_until"))

	u = performAuthorization(ts, "generic1", code, "")
	assertAuthorizationFailure(ts, u, "User is banned", "access_denied", "")
}
