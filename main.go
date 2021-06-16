package main

import (
	"context"
	_ "expvar"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/semconv"
	"go.opentelemetry.io/otel/trace"
)

type contextID int

const (
	logEntryID contextID = iota
)

var (
	httpClient = http.DefaultClient
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

	// Setup Datadog tracing if DD_SERVICE is set.
	ddService, isDDTrace := os.LookupEnv("DD_SERVICE")
	if isDDTrace {
		shutdownOTLP := initOTLP(ddService)
		defer shutdownOTLP()

		// Instrument http clients.
		auth0Client.Transport = otelhttp.NewTransport(auth0Client.Transport)
		httpClient = &http.Client{Transport: otelhttp.NewTransport(nil)}
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

	// Set up middleware.
	mux := loggingHandler(http.DefaultServeMux)

	if isDDTrace {
		mux = routeTagHandler(mux)
		mux = otelhttp.NewHandler(mux, "web.request")
	}

	// Set up http listener using provided command line parameters.
	var addr string
	if *bind == "*" {
		addr = ":" + *port
	} else {
		addr = *bind + ":" + *port
	}
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		logrus.WithField("err", err).Fatal("http listener error")
	}
}

// routeTagHandler sets the OpenTelemetry route to the current path. Based on
// otelhttp.WithRoute.
func routeTagHandler(inner http.Handler) http.Handler {
	mw := func(w http.ResponseWriter, r *http.Request) {
		span := trace.SpanFromContext(r.Context())
		span.SetAttributes(semconv.HTTPRouteKey.String(r.URL.Path))
		inner.ServeHTTP(w, r)
	}
	return http.HandlerFunc(mw)
}

// loggingHandler adds a logrus.Entry into the context of the current request.
func loggingHandler(inner http.Handler) http.Handler {
	mw := func(w http.ResponseWriter, r *http.Request) {
		ctx := withLogger(r.Context(), requestLogger(r))
		inner.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(mw)
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

	// Add trace and span IDs (if any) for log/trace correlation.
	span := trace.SpanFromContext(r.Context())
	if traceID := span.SpanContext().TraceID(); traceID.IsValid() {
		e = e.WithField("dd.trace_id", convertTraceID(traceID.String()))
	}
	if spanID := span.SpanContext().SpanID(); spanID.IsValid() {
		e = e.WithField("dd.span_id", convertTraceID(spanID.String()))
	}

	return e
}
