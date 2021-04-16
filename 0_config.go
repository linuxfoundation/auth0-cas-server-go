package main

import (
	"os"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

type config struct {
	Auth0Domain  string
	ClientID     string
	ClientSecret string

	CookieSecret string
}

// cfg provides parsed runtime configuration as a convenient global variable.
var cfg config

// init parses environment variables into the cfg global variable.
func init() {
	// Optionally load environment from a .env file.
	_ = godotenv.Load()

	cfg.Auth0Domain = os.Getenv("AUTH0_DOMAIN")
	if cfg.Auth0Domain == "" {
		logrus.Fatalln("AUTH0_DOMAIN not set")
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

}
