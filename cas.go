// Copyright The Linux Foundation and its contributors.
// SPDX-License-Identifier: MIT

// The auth0-cas-service-go service.
package main

// spell-checker:disable
import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

// spell-checker:enable

var store *sessions.CookieStore

type userAttributes struct {
	Username   string   `json:"https://sso.linuxfoundation.org/claims/username,omitempty"`
	Email      string   `json:"email,omitempty"`
	FullName   string   `json:"name,omitempty"`
	FamilyName string   `json:"family_name,omitempty"`
	GivenName  string   `json:"given_name,omitempty"`
	Zoneinfo   string   `json:"zoneinfo,omitempty"`
	Groups     []string `json:"https://sso.linuxfoundation.org/claims/groups,omitempty"`
}

func init() {
	store = sessions.NewCookieStore([]byte(cfg.CookieSecret))
	store.Options = &sessions.Options{
		Path:     "/cas/",
		MaxAge:   86400,
		Secure:   !cfg.InsecureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func casLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Expires", "Sun, 19 Nov 1978 05:00:00 GMT")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	params := r.URL.Query()

	service := params.Get("service")
	if service == "" {
		appLogger(r.Context()).Warning("service parameter is required")
		http.Error(w, "service parameter is required", http.StatusBadRequest)
		return
	}

	if _, err := url.Parse(service); err != nil {
		// We don't use this now, but better to catch here than in oauth2Callback.
		appLogger(r.Context()).Warning("invalid service URL")
		http.Error(w, "invalid service URL", http.StatusBadRequest)
		return
	}

	casClient, err := getAuth0ClientByService(r.Context(), service)
	if err != nil {
		appLogger(r.Context()).WithError(err).Error("error looking up service")
		http.Error(w, "error looking up service", http.StatusInternalServerError)
		return
	}
	if casClient == nil {
		appLogger(r.Context()).Warning("unknown service")
		http.Error(w, "unknown service", http.StatusForbidden)
		return
	}

	appLogger(r.Context()).WithField("auth0_client", casClient).Debug("found client")

	renew := params.Get("renew")

	gateway := params.Get("gateway")
	if renew == "" && gateway != "" {
		// TODO: use prompt=none to implement gateway mode below.
		http.Redirect(w, r, service, http.StatusFound)
		return
	}

	c := 9
	b := make([]byte, c)
	_, _ = rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	session, _ := store.Get(r, "cas-shim")
	session.Values[state] = service
	err = session.Save(r, w)
	if err != nil && err.Error() == "securecookie: the value is too long" {
		// The cookie can get too big if the user tries 10+ logins in the day
		// without returning from any of them.
		appLogger(r.Context()).Warning("cookie too large (bot or other bad client)")
		w.Header().Set("Retry-After", "86400")
		http.Error(w, "429 too many requests", http.StatusTooManyRequests)
		return
	}
	if err != nil {
		appLogger(r.Context()).WithError(err).Error("error saving session")
		http.Error(w, "500 internal server error", http.StatusInternalServerError)
		return
	}

	// Build the authorize (Auth0 login) URL.
	// TODO: use prompt=none to implement gateway mode.
	config := oauth2CfgFromAuth0Client(*casClient, r.Host)
	var authURL string
	switch {
	case renew != "":
		// Renew is "set" if present, regardless of value.
		authURL = config.AuthCodeURL(state, oauth2.SetAuthURLParam("prompt", "login"))
	default:
		authURL = config.AuthCodeURL(state)
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

func casLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Expires", "Sun, 19 Nov 1978 05:00:00 GMT")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	params := r.URL.Query()

	service := params.Get("service")
	if service == "" {
		// Also check for a v2 "url" param, but apply the same validation as a v3
		// "service" param.
		service = params.Get("url")
	}

	auth0Logout := fmt.Sprintf("https://%s/v2/logout", cfg.Auth0Domain)

	// Append client and returnTo if authorized.
	logoutParams := getLogoutParams(r.Context(), service)
	if logoutParams != nil {
		auth0Logout = auth0Logout + "?" + logoutParams.Encode()
	}

	http.Redirect(w, r, auth0Logout, http.StatusFound)
}

func casServiceValidate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Expires", "Sun, 19 Nov 1978 05:00:00 GMT")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	params := r.URL.Query()

	var useJSON bool
	formatParam := params.Get("format")
	switch {
	case formatParam == "JSON":
		useJSON = true
	case formatParam != "" && formatParam != "XML":
		outputFailure(r.Context(), w, nil, "INVALID_REQUEST", "invalid format", useJSON)
		return
	}

	service := params.Get("service")
	if service == "" {
		outputFailure(r.Context(), w, nil, "INVALID_REQUEST", "service parameter is required", useJSON)
		return
	}

	ticket := params.Get("ticket")
	if ticket == "" {
		outputFailure(r.Context(), w, nil, "INVALID_REQUEST", "ticket parameter is required", useJSON)
		return
	}

	pgtURL := params.Get("pgtUrl")
	if pgtURL != "" {
		outputFailure(r.Context(), w, nil, "INTERNAL_ERROR", "proxy callbacks not implemented", useJSON)
		return
	}

	if strings.HasPrefix(ticket, "PT-") {
		// We don't issue proxy tickets (/proxy always returns
		// UNAUTHORIZED_SERVICE), so any proxy ticket is not recognized.
		outputFailure(r.Context(), w, nil, "INVALID_TICKET", "ticket not recognized", useJSON)
		return
	}

	if !strings.HasPrefix(ticket, "ST-") {
		outputFailure(r.Context(), w, nil, "INVALID_TICKET_SPEC", "invalid ticket spec", useJSON)
		return
	}

	authCode := strings.TrimPrefix(ticket, "ST-A")
	if authCode == ticket {
		// Not having an ST-A prefix means the ticket is unknown; see oauth2Callback.
		outputFailure(r.Context(), w, nil, "INVALID_TICKET", "foreign ticket not recognized", useJSON)
		return
	}

	casClient, err := getAuth0ClientByService(r.Context(), service)
	if err != nil {
		outputFailure(r.Context(), w, err, "INTERNAL_ERROR", "error looking up service", useJSON)
		return
	}
	if casClient == nil {
		outputFailure(r.Context(), w, nil, "INVALID_SERVICE", "unknown service", useJSON)
		return
	}

	appLogger(r.Context()).WithField("auth0_client", casClient).Debug("found client")

	// Construct an OAuth2 config that lets us complete the authorization code
	// handshake to to get an access token.
	//
	// TODO: Currently, this service uses the access_token retrieved at this
	// point to make a request to the OIDC userinfo endpoint to get the user's
	// profile. HOWEVER, we might consider instead capturing the id_token
	// returned from the token URL. If we do this, we also would then validate
	// the id_token DIFFERENTLY based on whether the client was configured with
	// HS256 or RS256 token signing (similar to how we read the
	// token_endpoint_auth_method from the Auth0 client configuration). Since
	// RSA/JWKS type validation is more complex, we might only do id_token
	// parsing for HS256-configured clients, and fall back to the simpler
	// userinfo endpoint for RS256-configured clients. This gives us the
	// capability to skip the userinfo endpoint for performance gains (provided
	// the client is configured for it), without significantly increasing the
	// complexity of the codebase.
	config := oauth2CfgFromAuth0Client(*casClient, r.Host)
	appLogger(r.Context()).WithFields(logrus.Fields{
		"client_id": config.ClientID,
		"token_url": config.Endpoint.TokenURL,
		"code":      authCode,
	}).Debug("auth code exchange")
	token, err := config.Exchange(context.WithValue(r.Context(), oauth2.HTTPClient, httpClient), authCode)

	if err != nil {
		if rErr, ok := err.(*oauth2.RetrieveError); ok {
			if rErr.Response.StatusCode == 403 {
				// Rather than decoding the JSON payload, we can assume a 403 means the
				// auth code (as provided as a CAS service ticket) was invalid.
				appLogger(r.Context()).WithError(err).Debug("auth code exchange 403 response")
				outputFailure(r.Context(), w, nil, "INVALID_TICKET", "invalid ticket", useJSON)
				return
			}
		}
		// Handle any other error (non-403 responses or HTTP errors).
		outputFailure(r.Context(), w, err, "INTERNAL_ERROR", "error validating ticket", useJSON)
		return
	}

	uri := fmt.Sprintf("https://%s/userinfo", cfg.Auth0Domain)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, uri, nil)
	if err != nil {
		outputFailure(r.Context(), w, err, "INTERNAL_ERROR", "error creating user profile request", useJSON)
		return
	}
	token.SetAuthHeader(req)
	resp, err := httpClient.Do(req)
	if err != nil {
		outputFailure(r.Context(), w, err, "INTERNAL_ERROR", "error fetching user profile", useJSON)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		outputFailure(r.Context(), w, err, "INTERNAL_ERROR", "error reading user profile response", useJSON)
		return
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("userinfo returned %v: %s", resp.StatusCode, string(bodyBytes))
		outputFailure(r.Context(), w, err, "INTERNAL_ERROR", "user profile response error", useJSON)
		return
	}

	user := new(userAttributes)
	err = json.Unmarshal(bodyBytes, user)
	if err != nil {
		outputFailure(r.Context(), w, err, "INTERNAL_ERROR", "user profile parse error", useJSON)
		return
	}

	success := casAuthenticationSuccess{
		User: user.Username,
		Attributes: casAttributes{
			Email:      user.Email,
			FullName:   user.FullName,
			GivenName:  user.GivenName,
			FamilyName: user.FamilyName,
			Timezone:   user.Zoneinfo,
			Groups:     user.Groups,
		},
	}
	output, err := validationResponse(&success, nil, useJSON)
	if err != nil {
		appLogger(r.Context()).WithError(err).WithField("success", success).Error("error generating validation response")
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "error generating validation response", http.StatusInternalServerError)
		return
	}

	appLogger(r.Context()).WithField("body", output).Debug("sending validation response")

	switch useJSON {
	case true:
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	default:
		w.Header().Set("Content-Type", "application/xml;charset=UTF-8")
	}
	fmt.Fprintf(w, "%s\n", output)
}

func casProxy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Expires", "Sun, 19 Nov 1978 05:00:00 GMT")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	params := r.URL.Query()

	var useJSON bool
	formatParam := params.Get("format")
	switch {
	case formatParam == "JSON":
		useJSON = true
	case formatParam != "" && formatParam != "XML":
		outputFailure(r.Context(), w, nil, "INVALID_REQUEST", "invalid format", useJSON)
		return
	}

	pgt := params.Get("pgt")
	if pgt == "" {
		outputFailure(r.Context(), w, nil, "INVALID_REQUEST", "pgt parameter is required", useJSON)
		return
	}

	targetService := params.Get("targetService")
	if targetService == "" {
		outputFailure(r.Context(), w, nil, "INVALID_REQUEST", "targetService parameter is required", useJSON)
		return
	}

	// Deny all proxy-grant-ticket requests.
	outputFailure(r.Context(), w, nil, "UNAUTHORIZED_SERVICE", "not authorized for proxy requests", useJSON)
}

func oauth2Callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Expires", "Sun, 19 Nov 1978 05:00:00 GMT")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	params := r.URL.Query()

	errParam := params.Get("error")
	errDescription := params.Get("error_description")
	if errParam == "access_denied" {
		// Consider this a warning-level error for logging purposes.
		err := fmt.Errorf("%s: %s", errParam, errDescription)
		appLogger(r.Context()).WithError(err).Warning("login aborted")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if errParam != "" {
		err := fmt.Errorf("%s: %s", errParam, errDescription)
		appLogger(r.Context()).WithError(err).Error("login error")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	code := params.Get("code")
	if code == "" {
		appLogger(r.Context()).Warning("invalid request")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	state := params.Get("state")
	if state == "" {
		appLogger(r.Context()).Warning("missing state")
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}

	session, _ := store.Get(r, "cas-shim")
	var service string
	var ok bool
	if service, ok = session.Values[state].(string); !ok {
		appLogger(r.Context()).Warning("session missing or expired")
		http.Error(w, "session missing or expired", http.StatusBadRequest)
		return
	}

	session.Values[state] = nil
	_ = session.Save(r, w)

	serviceURL, err := url.Parse(service)
	if err != nil {
		appLogger(r.Context()).Warning("invalid service URL")
		http.Error(w, "invalid service URL", http.StatusBadRequest)
		return
	}

	// ST- is required by CAS spec, and we add "A" for "authentication code", in
	// case we support different ticket types in the future.
	newParams := serviceURL.Query()
	newParams.Set("ticket", fmt.Sprintf("ST-A%s", code))
	serviceURL.RawQuery = newParams.Encode()

	http.Redirect(w, r, serviceURL.String(), http.StatusFound)
}

func oauth2CfgFromAuth0Client(client auth0ClientStub, casHostname string) oauth2.Config {
	var authStyle oauth2.AuthStyle
	switch client.TokenEndpointAuthMethod {
	case "client_secret_post":
		authStyle = oauth2.AuthStyleInParams
	case "client_secret_basic":
		authStyle = oauth2.AuthStyleInHeader
	}

	return oauth2.Config{
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   fmt.Sprintf("https://%s/authorize", cfg.Auth0Domain),
			TokenURL:  fmt.Sprintf("https://%s/oauth/token", cfg.Auth0Domain),
			AuthStyle: authStyle,
		},
		RedirectURL: fmt.Sprintf("https://%s/cas/oidc_callback", casHostname),
		Scopes:      []string{"openid", "profile", "email"},
	}
}

func getLogoutParams(ctx context.Context, returnTo string) *url.Values {
	if returnTo == "" {
		return nil
	}

	returnURL, err := url.Parse(returnTo)
	if err != nil {
		// Warn about the error and continue.
		appLogger(ctx).WithFields(logrus.Fields{
			"returnTo":      returnTo,
			logrus.ErrorKey: err,
		}).Warn("ignoring invalid returnTo URL")
		return nil
	}

	casClient, err := getAuth0ClientByService(ctx, returnTo)
	if err != nil {
		// Warn about the error and continue.
		appLogger(ctx).WithFields(logrus.Fields{
			"returnTo":      returnTo,
			logrus.ErrorKey: err,
		}).Warn("ignoring unexpected error validating logout redirection")
		return nil
	}

	if casClient == nil {
		// No cas_service configurations matched the requested logout redirect.
		appLogger(ctx).WithField("returnTo", returnTo).Warn("ignoring unauthorized logout redirection")
		return nil
	}

	// There is a match against cas_service, now we also have to see if it's in
	// allowed_logout_urls for the client.
	returnURL.RawQuery = ""
	returnNoQueryOrTrailingSlash := strings.TrimSuffix(returnURL.String(), "/")
	for _, allowedLogoutValue := range casClient.AllowedLogoutURLs {
		allowedLogoutURL, err := url.Parse(allowedLogoutValue)
		if err != nil {
			appLogger(ctx).WithField("allowed_logout_url", allowedLogoutValue).Warn("unable to parse allowed_logout_urls value")
			continue
		}
		allowedLogoutURL.RawQuery = ""
		allowedLogoutNoQueryOrTrailingSlash := strings.TrimSuffix(allowedLogoutURL.String(), "/")
		if matched, _ := filepath.Match(allowedLogoutNoQueryOrTrailingSlash, returnNoQueryOrTrailingSlash); matched {
			v := &url.Values{}
			v.Add("client_id", casClient.ClientID)
			v.Add("returnTo", returnTo)
			return v
		}
	}

	appLogger(ctx).WithFields(logrus.Fields{
		"returnTo":  returnTo,
		"client_id": casClient.ClientID,
	}).Warn("returnTo not allowed by allowed_logout_urls")

	return nil
}

// outputFailure handles a common case of reporting a problem to the
// /cas/serviceValidate URL, which is expected to return a properly-formatted
// error. This logs the issue, and formats and outputs the response (default
// 200 status code). If the response cannot be formatted, an additional error
// is logged and a plain-text message and 500 response is output.
func outputFailure(ctx context.Context, w http.ResponseWriter, err error, code, description string, useJSON bool) {
	switch {
	case err != nil:
		appLogger(ctx).WithError(err).Error(description)
	default:
		appLogger(ctx).Warning(description)
	}

	failure := casAuthenticationFailure{code, description}
	output, err := validationResponse(nil, &failure, useJSON)
	if err != nil {
		appLogger(ctx).WithError(err).WithField("failure", failure).Error("error generating validation response")
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "error generating validation response", http.StatusInternalServerError)
		return
	}
	switch useJSON {
	case true:
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	default:
		w.Header().Set("Content-Type", "application/xml;charset=UTF-8")
	}
	fmt.Fprintf(w, "%s\n", output)
}
