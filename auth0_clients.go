// Copyright The Linux Foundation and its contributors.
// SPDX-License-Identifier: MIT

// The auth0-cas-service-go service.
package main

// spell-checker:disable
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2/clientcredentials"
)

// spell-checker:enable

var (
	auth0Client *http.Client
	auth0Cache  = cache.New(60*time.Minute, 5*time.Minute)
)

func init() {
	auth0AuthConfig := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     fmt.Sprintf("https://%s.auth0.com/oauth/token", cfg.Auth0Tenant),
		EndpointParams: url.Values{
			"audience": {fmt.Sprintf("https://%s.auth0.com/api/v2/", cfg.Auth0Tenant)},
		},
	}
	auth0Client = auth0AuthConfig.Client(context.Background())
}

type auth0ClientJWTCfgStub struct {
	Alg string `json:"alg"`
}

type auth0ClientStub struct {
	ClientID                string                `json:"client_id"`
	ClientSecret            string                `json:"client_secret,omitempty"`
	Name                    string                `json:"name"`
	AllowedLogoutURLs       []string              `json:"allowed_logout_urls"`
	JWTConfiguration        auth0ClientJWTCfgStub `json:"jwt_configuration"`
	TokenEndpointAuthMethod string                `json:"token_endpoint_auth_method"`
	ClientMetadata          map[string]string     `json:"client_metadata"`
}

type auth0ClientsResponse struct {
	Total   uint64            `json:"total"`
	Start   uint64            `json:"start"`
	Limit   uint64            `json:"limit"`
	Clients []auth0ClientStub `json:"clients"`
}

func getAuth0Clients(ctx context.Context) ([]auth0ClientStub, error) {
	// Get an expiring lock on auth0-clients mutex to avoid concurrent lookups.
	for {
		err := auth0Cache.Add("mutex/auth0-clients", true, 10*time.Second)
		if err == nil {
			defer auth0Cache.Delete("mutex/auth0-clients")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if item, exists := auth0Cache.Get("auth0-clients"); exists {
		// Using cached response of all clients (all pages).
		appLogger(ctx).Debug("using cached auth0-clients result")
		return item.([]auth0ClientStub), nil
	}

	page := 0

	v := &url.Values{}
	v.Add("fields", "client_id,client_secret,name,allowed_logout_urls,jwt_configuration,token_endpoint_auth_method,client_metadata")
	v.Add("include_fields", "true")
	v.Add("page", strconv.Itoa(page))
	v.Add("per_page", "100")
	v.Add("include_totals", "true")
	v.Add("is_global", "false")
	v.Add("app_type", "regular_web")

	allClients := []auth0ClientStub{}

	for {
		uri := fmt.Sprintf("https://%s.auth0.com/api/v2/clients?%s", cfg.Auth0Tenant, v.Encode())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
		if err != nil {
			return nil, err
		}
		resp, err := auth0Client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			appLogger(ctx).WithFields(logrus.Fields{
				"status": resp.StatusCode,
				"body":   string(bodyBytes),
			}).Error("Auth0 get_users error")
			return nil, errors.New("Auth0 get_clients error")
		}

		parsedResp := new(auth0ClientsResponse)
		err = json.Unmarshal(bodyBytes, parsedResp)
		if err != nil {
			return nil, err
		}

		allClients = append(allClients, parsedResp.Clients...)

		if parsedResp.Total <= parsedResp.Start+parsedResp.Limit {
			// No additional pages.
			break
		}

		// Loop with next page for additional results.
		page++
		v.Set("page", strconv.Itoa(page))
	}

	auth0Cache.Set("auth0-clients", allClients, 15*time.Minute)

	return allClients, nil
}

func getAuth0ClientByService(ctx context.Context, serviceURL string) (*auth0ClientStub, error) {
	service, err := url.Parse(serviceURL)
	if err != nil {
		// Simply treat malformed URLs as "no match".
		return nil, nil
	}
	// Strip queries and fragments from the URL.
	service.RawQuery = ""
	service.Fragment = ""
	serviceURL = service.String()

	if item, exists := auth0Cache.Get("cas-service-url/" + url.PathEscape(serviceURL)); exists {
		client := item.(auth0ClientStub)
		return &client, nil
	}

	// Compare against cached globs.
	if item, exists := auth0Cache.Get("cas-service-globs"); exists {
		for glob, client := range item.(map[string]auth0ClientStub) {
			var match bool
			match, err = doublestar.Match(glob, serviceURL)
			if err != nil {
				appLogger(ctx).WithFields(logrus.Fields{
					"pattern":       glob,
					logrus.ErrorKey: err,
				}).Warning("unexpected bad cas_service glob in cache")
				continue
			}
			if !match {
				continue
			}

			// There is a match
			appLogger(ctx).WithFields(logrus.Fields{"service": serviceURL, "glob": glob, "auth0_client": client.Name}).Debug("matched service in glob cache")
			auth0Cache.Set("cas-service-url/"+url.PathEscape(serviceURL), client, cache.NoExpiration)
			return &client, nil
		}
	}

	// If cache missing, or no matches, continue with direct client lookup, and
	// update the glob cache.
	clients, err := getAuth0Clients(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting Auth0 clients: %s", err)
	}

	// For some reason, using a pointer to store a reference to the match doesn't
	// work.
	var clientMatch auth0ClientStub

	globs := make(map[string]auth0ClientStub)
	for _, client := range clients {
		if client.ClientMetadata == nil || client.ClientMetadata["cas_service"] == "" {
			continue
		}

		if client.TokenEndpointAuthMethod != "client_secret_post" && client.TokenEndpointAuthMethod != "client_secret_basic" {
			appLogger(ctx).WithFields(logrus.Fields{
				"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
				"auth0_client":               client.Name,
			}).Warning("client with cas_service has unsupported token_endpoint_auth_method")
			continue
		}

		serviceGlobs := strings.Split(client.ClientMetadata["cas_service"], ",")

		// Iterate over any comma-delimited cas_service globs in the
		// client_metadata.
		for _, glob := range serviceGlobs {
			match, err := doublestar.Match(glob, serviceURL)
			if err != nil {
				appLogger(ctx).WithFields(logrus.Fields{
					"pattern":       glob,
					logrus.ErrorKey: err,
				}).Warning("ignoring bad cas_service glob")
				continue
			}
			// Store the glob-to-client lookup (for cache).
			globs[glob] = client

			if !match {
				continue
			}

			appLogger(ctx).WithFields(logrus.Fields{"service": serviceURL, "glob": glob, "auth0_client": client.Name}).Debug("matched service")
			// If the glob matches, save the match, but keep processing remaining
			// comma-delimited globs AND clients to complete the glob-to-client cache
			// update.
			auth0Cache.Set("cas-service-url/"+url.PathEscape(serviceURL), client, cache.NoExpiration)
			clientMatch = client
		}
	}

	// Update the glob-to-client lookup cache.
	auth0Cache.Set("cas-service-globs", globs, time.Duration(400)*time.Hour)

	// Return the match, if any, from iterating through clients while rebuilding
	// glob cache. Because updating a pointer wasn't working, we check for a zero
	// value on ClientID.
	if clientMatch.ClientID == "" {
		return nil, nil
	}
	return &clientMatch, nil
}
