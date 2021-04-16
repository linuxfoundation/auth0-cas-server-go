package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var store *sessions.CookieStore

type userAttributes struct {
	Username   string   `json:"username,omitempty"`
	Email      string   `json:"email,omitempty"`
	FullName   string   `json:"name,omitempty"`
	FamilyName string   `json:"family_name,omitempty"`
	GivenName  string   `json:"given_name,omitempty"`
	Zoneinfo   string   `json:"zoneinfo,omitempty"`
	Groups     []string `json:"https://sso.linuxfoundation.org/claims/groups",omitempty`
}

func init() {
	store = sessions.NewCookieStore([]byte(cfg.CookieSecret))
	// TODO: SameSite, Secure
	store.Options = &sessions.Options{
		Path:     "/cas/",
		MaxAge:   86400,
		HttpOnly: true,
	}
}

func casLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Expires", "Sun, 19 Nov 1978 05:00:00 GMT")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != "GET" && r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	params := r.URL.Query()

	service := params.Get("service")
	if service == "" {
		appLogger(r).Warning("service parameter is required")
		http.Error(w, "service parameter is required", http.StatusBadRequest)
		return
	}

	if _, err := url.Parse(service); err != nil {
		// We don't use this now, but better to catch here than in oauth2Callback.
		appLogger(r).Warning("invalid service URL")
		http.Error(w, "invalid service URL", http.StatusBadRequest)
		return
	}

	gateway, _ := strconv.ParseBool(params.Get("gateway"))
	if gateway {
		appLogger(r).Error("gateway mode not implemented")
		http.Error(w, "gateway mode not implemented", http.StatusNotImplemented)
		return
	}

	renew, _ := strconv.ParseBool(params.Get("renew"))

	casClient, err := getAuth0ClientByService(r.Context(), service)
	if err != nil {
		appLogger(r).WithError(err).Error("error looking up service")
		http.Error(w, "error looking up service", http.StatusInternalServerError)
		return
	}
	if casClient == nil {
		appLogger(r).Warning("unknown service")
		http.Error(w, "unknown service", http.StatusForbidden)
		return
	}

	appLogger(r).WithField("client", casClient).Debug("found client")

	c := 9
	b := make([]byte, c)
	_, _ = rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	session, _ := store.Get(r, "cas-shim")
	session.Values[state] = service
	// XXX: the cookie can get too big if the user tries 10+ logins in the day
	// without returning from any of them.
	err = session.Save(r, w)
	if err != nil {
		appLogger(r).WithError(err).Error("error saving session")
		http.Error(w, "500 internal server error", http.StatusInternalServerError)
		return
	}

	// Build the authorize (Auth0 login) URL.
	// TODO: use prompt=none to implement gateway mode.
	config := oauth2CfgFromAuth0Client(*casClient, r.Host)
	var authURL string
	switch renew {
	case true:
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

	if r.Method != "GET" && r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	auth0Logout := fmt.Sprintf("https://%s/v2/logout", cfg.Auth0Domain)

	http.Redirect(w, r, auth0Logout, http.StatusFound)
}

func casServiceValidate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Expires", "Sun, 19 Nov 1978 05:00:00 GMT")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != "GET" && r.Method != "POST" {
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
		appLogger(r).Error("format not implemented")
		http.Error(w, "format not implemented", http.StatusNotImplemented)
		return
	}

	service := params.Get("service")
	if service == "" {
		outputFailure(w, r, nil, "INVALID_REQUEST", "service parameter is required", useJSON)
		return
	}

	ticket := params.Get("ticket")
	if ticket == "" {
		outputFailure(w, r, nil, "INVALID_REQUEST", "ticket parameter is required", useJSON)
		return
	}

	authCode := strings.TrimPrefix(ticket, "ST-A")
	if authCode == ticket {
		// Not having an ST-A prefix means the ticket is unknown; see oauth2Callback.
		outputFailure(w, r, nil, "INVALID_TICKET", "ticket failed validation", useJSON)
		return
	}

	casClient, err := getAuth0ClientByService(r.Context(), service)
	if err != nil {
		outputFailure(w, r, err, "INTERNAL_ERROR", "error looking up service", useJSON)
		return
	}
	if casClient == nil {
		outputFailure(w, r, nil, "INVALID_SERVICE", "unknown service", useJSON)
		return
	}

	appLogger(r).WithField("client", casClient).Debug("found client")

	config := oauth2CfgFromAuth0Client(*casClient, r.Host)
	token, err := config.Exchange(r.Context(), authCode)

	if err != nil {
		if rErr, ok := err.(*oauth2.RetrieveError); ok {
			if rErr.Response.StatusCode == 403 {
				// Rather than decoding the JSON payload, we can assume a 403 means the
				// auth code (as provided as a CAS service ticket) was invalid.
				outputFailure(w, r, nil, "INVALID_TICKET", "invalid ticket", useJSON)
				return
			}
		}
		// Handle any other error (non-403 responses or HTTP errors).
		outputFailure(w, r, err, "INTERNAL_ERROR", "error validating ticket", useJSON)
		return
	}

	uri := fmt.Sprintf("https://%s/userinfo", cfg.Auth0Domain)
	req, err := http.NewRequestWithContext(r.Context(), "GET", uri, nil)
	if err != nil {
		outputFailure(w, r, err, "INTERNAL_ERROR", "error creating user profile request", useJSON)
		return
	}
	token.SetAuthHeader(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		outputFailure(w, r, err, "INTERNAL_ERROR", "error fetching user profile", useJSON)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		outputFailure(w, r, err, "INTERNAL_ERROR", "error reading user profile response", useJSON)
		return
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("userinfo returned %v: %s", resp.StatusCode, string(bodyBytes))
		outputFailure(w, r, err, "INTERNAL_ERROR", "user profile response error", useJSON)
		return
	}

	user := new(userAttributes)
	err = json.Unmarshal(bodyBytes, user)
	if err != nil {
		outputFailure(w, r, err, "INTERNAL_ERROR", "user profile parse error", useJSON)
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
		appLogger(r).WithError(err).WithField("success", success).Error("error generating validation response")
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

func oauth2Callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Expires", "Sun, 19 Nov 1978 05:00:00 GMT")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	params := r.URL.Query()

	errParam := params.Get("error")
	errDescription := params.Get("error_description")
	if errParam != "" {
		err := fmt.Errorf("%s: %s", errParam, errDescription)
		appLogger(r).WithError(err).Error("login error")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	code := params.Get("code")
	if code == "" {
		appLogger(r).Warning("invalid request")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	state := params.Get("state")
	if state == "" {
		appLogger(r).Warning("missing state")
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}

	session, _ := store.Get(r, "cas-shim")
	var service string
	var ok bool
	if service, ok = session.Values[state].(string); !ok {
		appLogger(r).Warning("session missing or expired")
		http.Error(w, "session missing or expired", http.StatusBadRequest)
		return
	}

	session.Values[state] = nil
	_ = session.Save(r, w)

	serviceURL, err := url.Parse(service)
	if err != nil {
		appLogger(r).Warning("invalid service URL")
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

// outputFailure handles a common case of reporting a problem to the
// /cas/serviceValidate URL, which is expected to return a properly-formatted
// error. This logs the issue, and formats and outputs the response (default
// 200 status code). If the response cannot be formatted, an additional error
// is logged and a plain-text message and 500 response is output.
func outputFailure(w http.ResponseWriter, r *http.Request, err error, code, description string, useJSON bool) {
	switch {
	case err != nil:
		appLogger(r).WithError(err).Error(description)
	default:
		appLogger(r).Warning(description)
	}

	failure := casAuthenticationFailure{code, description}
	output, err := validationResponse(nil, &failure, useJSON)
	if err != nil {
		appLogger(r).WithError(err).WithField("failure", failure).Error("error generating validation response")
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
