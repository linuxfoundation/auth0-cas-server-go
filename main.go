package main

import (
	"context"
	_ "expvar"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/evalphobia/logrus_fluent"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
)

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
	var logJSON = flag.Bool("json", false, "force json logging (default to environment detection)")
	var noTrace = flag.Bool("notrace", false, "disable OTLP tracing output")
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
	_, isECS := os.LookupEnv("ECS_CONTAINER_METADATA_URI_V4")
	fluentHost, useFluent := os.LookupEnv("FLUENT_HOST")
	switch {
	case isElasticBeanstalk || *logJSON:
		// If running in Elastic Beanstalk, dd-agent should be in place to scrape
		// logs.
		logrus.SetFormatter(&logrus.JSONFormatter{})
	case isECS && !useFluent:
		// Assume output to CloudWatch logs which has native timestamps. Use
		// "message" for cleaner integration with log aggregation service.
		logrus.SetFormatter(&logrus.JSONFormatter{
			DisableTimestamp: true,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyMsg: "message",
			},
		})
	case useFluent:
		var fluentPort int64 = 5170
		if fluentPortEnv, ok := os.LookupEnv("FLUENT_PORT"); ok {
			var err error
			fluentPort, err = strconv.ParseInt(fluentPortEnv, 10, 32)
			if err != nil {
				logrus.WithField("fluent_port", fluentPortEnv).WithError(err).Fatal("unable to parse FLUENT_PORT")
			}
		}
		hook, err := logrus_fluent.New(fluentHost, int(fluentPort))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"host":          fluentHost,
				"port":          fluentPort,
				logrus.ErrorKey: err,
			}).Fatal("could not set up fluentd logger")
		}
		hook.SetTag(serviceName + ".log")

		// Convert error struct to string.
		hook.AddFilter(logrus.ErrorKey, logrus_fluent.FilterError)

		logrus.AddHook(hook)
	}

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
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		logrus.WithError(err).Fatal("http listener error")
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
		return logrus.NewEntry(logrus.StandardLogger())
	}

	if logger, ok := ctx.Value(logEntryID).(*logrus.Entry); ok {
		return logger
	}

	return logrus.NewEntry(logrus.StandardLogger())
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
	spanContext := trace.SpanContextFromContext(r.Context())
	if traceID := spanContext.TraceID(); traceID.IsValid() {
		e = e.WithField("dd.trace_id", convertTraceID(traceID.String()))
	}
	if spanID := spanContext.SpanID(); spanID.IsValid() {
		e = e.WithField("dd.span_id", convertTraceID(spanID.String()))
	}

	return e
}
