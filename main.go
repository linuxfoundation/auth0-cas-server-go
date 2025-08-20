// Copyright The Linux Foundation and its contributors.
// SPDX-License-Identifier: MIT

// The auth0-cas-service-go service.
package main

// spell-checker:disable
import (
	"context"
	_ "expvar"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	"go.opentelemetry.io/otel/trace"
)

// spell-checker:enable

type contextID int

const (
	logEntryID  contextID = iota
	serviceName           = "auth0-cas-server-go"
)

var (
	httpClient = http.DefaultClient
)

// main parses optional flags and starts http listener.
func main() {
	var debug = flag.Bool("d", false, "enable debug logging")
	var logJSON = flag.Bool("json", false, "force json logging to console (default: autodetect environment)")
	var noTrace = flag.Bool("no-trace", false, "disable OTLP tracing output")
	var port = flag.String("p", "5000", "port")
	var bind = flag.String("bind", "*", "interface to bind on")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()

	// Configure slog logging.
	var logLevel slog.Level
	if os.Getenv("DEBUG") != "" || *debug {
		logLevel = slog.LevelDebug
	} else {
		logLevel = slog.LevelInfo
	}

	_, isECS := os.LookupEnv("ECS_CONTAINER_METADATA_URI_V4")
	var handler slog.Handler
	switch {
	case isECS:
		// Assume ECS is logging to CloudWatch logs and use JSON format.
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel,
			ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
				// The timestamp attribute will be redundant with the CloudWatch logs
				// timestamp.
				if a.Key == slog.TimeKey {
					return slog.Attr{}
				}
				// Use "message" instead of "msg" for compatibility with external log
				// aggregators.
				if a.Key == slog.MessageKey {
					return slog.String("message", a.Value.String())
				}
				return a
			},
		})
	case *logJSON:
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	default:
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	// Instrument Open Telemetry.
	if !*noTrace {
		// Start OTLP forwarder and register the global tracing provider.
		shutdownOTLP := initOTLP()
		defer shutdownOTLP()

		// Instrument HTTP clients.
		auth0Client.Transport = otelhttp.NewTransport(
			auth0Client.Transport,
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				// Update the span name to include the remote host. This is disabled by
				// default to avoid high-cardinality problems for services that connect
				// to many different servers, such as with dynamic service discovery.
				// This should not be a problem for this service.
				return fmt.Sprintf("%s %s", r.Method, r.URL.Host)
			}),
		)
		httpClient = &http.Client{Transport: otelhttp.NewTransport(nil)}
	}

	// Support GET/POST monitoring "ping".
	http.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) {
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

	// Add middleware to instrument our HTTP server.
	if !*noTrace {
		// Per OpenTelemetry spec, http.server_name should be a *configured* (not
		// determined by incoming request headers) virtual host, otherwise *unset*.
		vhost := ""
		mux = routeTagHandler(mux)
		mux = otelhttp.NewHandler(
			mux,
			vhost,
			otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
				// Use "vhost/path/to/resource" as the span name. Pattern-based routers
				// should not do this: but this service only serves up discrete paths.
				return fmt.Sprintf("%s%s", operation, r.URL.Path)
			}),
		)
	}

	// Set up http listener using provided command line parameters.
	var addr string
	if *bind == "*" {
		addr = ":" + *port
	} else {
		addr = *bind + ":" + *port
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
	err := server.ListenAndServe()
	if err != nil {
		slog.Error("http listener error", "error", err)
		os.Exit(1)
	}
}

// routeTagHandler sets the OpenTelemetry route to the current path. Based on
// otelhttp.WithRoute, but implemented as middleware. This is different from
// instrumenting the request itself, which is done with otelhttp.NewHandler.
func routeTagHandler(inner http.Handler) http.Handler {
	mw := func(w http.ResponseWriter, r *http.Request) {
		span := trace.SpanFromContext(r.Context())
		// (Note: for pattern-based routers, replace r.URL.Path with the matched
		// pattern!)
		span.SetAttributes(semconv.HTTPRouteKey.String(r.URL.Path))
		inner.ServeHTTP(w, r)
	}
	return http.HandlerFunc(mw)
}

// loggingHandler adds a slog.Logger into the context of the current request.
func loggingHandler(inner http.Handler) http.Handler {
	mw := func(w http.ResponseWriter, r *http.Request) {
		ctx := withLogger(r.Context(), requestLogger(r))
		inner.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(mw)
}

func withLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, logEntryID, logger)
}

func appLogger(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return slog.Default()
	}

	if logger, ok := ctx.Value(logEntryID).(*slog.Logger); ok {
		return logger
	}

	return slog.Default()
}

func requestLogger(r *http.Request) *slog.Logger {
	logger := slog.Default().With(
		"method", r.Method,
		"url", r.URL.Path,
		"query", r.URL.RawQuery,
	)

	var headerIP string
	if cfg.RemoteIPHeader != "" {
		headerIP = r.Header.Get(cfg.RemoteIPHeader)
	}

	if referer := r.Header.Get("Referer"); referer != "" {
		logger = logger.With("referer", referer)
	}

	switch headerIP {
	case "":
		// Log the client IP.
		logger = logger.With("client", r.RemoteAddr)
	default:
		// Log the IP recorded in the configured header.
		logger = logger.With("client", headerIP)
	}

	// Add trace and span IDs (if any) for log/trace correlation.
	spanContext := trace.SpanContextFromContext(r.Context())
	if traceID := spanContext.TraceID(); traceID.IsValid() {
		logger = logger.With("trace_id", traceID.String(), "dd.trace_id", convertTraceID(traceID.String()))
	}
	if spanID := spanContext.SpanID(); spanID.IsValid() {
		logger = logger.With("span_id", spanID.String(), "dd.span_id", convertTraceID(spanID.String()))
	}
	logger = logger.With("trace_flags", spanContext.TraceFlags().String())

	return logger
}
