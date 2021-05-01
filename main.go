package main

import (
	"context"
	_ "expvar"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
)

type contextID int

const (
	logEntryID contextID = iota
)

// main parses optional flags and starts http listener.
func main() {
	var debug = flag.Bool("d", false, "enable debug logging")
	var logJSON = flag.Bool("json", false, "force json logging (default to environment detection)")
	var port = flag.String("p", "5000", "port")
	var bind = flag.String("bind", "*", "interface to bind on")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()

	// Optional debug logging.
	if os.Getenv("DEBUG") != "" || *debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	_, isElasticBeanstalk := os.LookupEnv("APP_DEPLOY_DIR")
	_, isECS := os.LookupEnv("ECS_CLUSTER")
	if isElasticBeanstalk || isECS || *logJSON {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	}

	// Support GET/POST monitoring "ping".
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK\n")
	})

	// CAS protocol 2 and 3.
	http.HandleFunc("/cas/login", casLogin)
	http.HandleFunc("/cas/logout", casLogout)
	http.HandleFunc("/cas/serviceValidate", casServiceValidate)
	http.HandleFunc("/cas/p3/serviceValidate", casServiceValidate)
	http.HandleFunc("/cas/proxyValidate", casServiceValidate)
	http.HandleFunc("/cas/p3/proxyValidate", casServiceValidate)
	http.HandleFunc("/cas/proxy", casProxy)

	// Interstitial page to implement OIDC callback to redirect to CAS service.
	http.HandleFunc("/cas/oidc_callback", oauth2Callback)

	// Set up http listener using provided command line parameters.
	var addr string
	if *bind == "*" {
		addr = ":" + *port
	} else {
		addr = *bind + ":" + *port
	}
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		logrus.WithField("err", err).Fatal("http listener error")
	}

}

func withLogger(ctx context.Context, logger *logrus.Entry) context.Context {
	return context.WithValue(ctx, logEntryID, logger)
}

func appLogger(ctx context.Context) *logrus.Entry {
	if ctx == nil {
		return &logrus.Entry{}
	}

	if logger, ok := ctx.Value(logEntryID).(*logrus.Entry); ok {
		return logger
	}

	return &logrus.Entry{}
}

func requestLogger(r *http.Request) *logrus.Entry {
	e := logrus.WithFields(logrus.Fields{
		"method": r.Method,
		"url":    r.URL.Path,
		"query":  r.URL.RawQuery,
	})

	var headerIP string
	if cfg.RemoteIPHeader != "" {
		headerIP = r.Header.Get(cfg.RemoteIPHeader)
	}

	if referer := r.Header.Get("Referer"); referer != "" {
		e = e.WithField("referer", referer)
	}

	switch headerIP {
	case "":
		// Log the client IP.
		e = e.WithField("client", r.RemoteAddr)
	default:
		// Log the IP recorded in the configured header.
		e = e.WithField("client", headerIP)
	}

	return e
}
