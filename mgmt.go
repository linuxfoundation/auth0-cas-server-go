package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2/clientcredentials"
)

var (
	auth0Client *http.Client
	auth0Cache  = cache.New(60*time.Minute, 5*time.Minute)
)

func init() {
	auth0AuthConfig := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     fmt.Sprintf("https://%s/oauth/token", cfg.Auth0Domain),
		EndpointParams: url.Values{
			"audience": {fmt.Sprintf("https://%s/api/v2/", cfg.Auth0Domain)},
		},
	}
	auth0Client = auth0AuthConfig.Client(context.Background())
}

func getAuth0Clients(ctx context.Context) {
}
