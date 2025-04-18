// Copyright The Linux Foundation and its contributors.
// SPDX-License-Identifier: MIT

// The auth0-cas-service-go service.
package main

// spell-checker:disable
import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

// spell-checker:enable

type config struct {
	Auth0Tenant  string
	Auth0Domain  string
	ClientID     string
	ClientSecret string

	CookieSecret   string
	InsecureCookie bool

	RemoteIPHeader string
}

// cfg provides parsed runtime configuration as a convenient global variable.
var cfg config

// init parses environment variables into the cfg global variable.
func init() {
	// Optionally load environment from a .env file.
	_ = godotenv.Load()

	cfg.Auth0Tenant = os.Getenv("AUTH0_TENANT")
	if cfg.Auth0Tenant == "" {
		logrus.Fatalln("AUTH0_TENANT not set")
	}
	if strings.ContainsAny(strings.TrimSuffix(cfg.Auth0Tenant, ".us"), "./:") {
		// .us is allowed, but otherwise AUTH0_TENANT cannot contain anything
		// looking like a domain name or URL.
		logrus.Fatalln("invalid AUTH0_TENANT")
	}
	cfg.Auth0Domain = os.Getenv("AUTH0_DOMAIN")
	if cfg.Auth0Domain == "" {
		cfg.Auth0Domain = fmt.Sprintf("%s.auth0.com", cfg.Auth0Tenant)
	}
	cfg.ClientID = os.Getenv("CLIENT_ID")
	if cfg.ClientID == "" {
		logrus.Fatalln("CLIENT_ID not set")
	}
	cfg.ClientSecret = os.Getenv("CLIENT_SECRET")
	if cfg.ClientSecret == "" {
		logrus.Fatalln("CLIENT_SECRET not set")
	}

	cfg.CookieSecret = os.Getenv("COOKIE_SECRET")
	if cfg.CookieSecret == "" {
		logrus.Fatalln("COOKIE_SECRET not set")
	}

	insecureCookie := os.Getenv("INSECURE_COOKIE")
	if insecureCookie != "" && insecureCookie != "false" && insecureCookie != "0" {
		cfg.InsecureCookie = true
	}

	// Look up client IPs in a header set by a proxy, if present. Only intended
	// for simple headers with one client IP; does not parse X-Forwarded-For.
	cfg.RemoteIPHeader = os.Getenv("REMOTE_IP_HEADER")
}
