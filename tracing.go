package main

import (
	"context"
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
)

type otelErrorHandler struct{}

func (h *otelErrorHandler) Handle(err error) {
	logrus.WithError(err).Error("opentelemetry-go error")
}

func init() {
	otel.SetErrorHandler(&otelErrorHandler{})
}

// Initializes an OTLP exporter, and configures the corresponding trace and
// metric providers. Returns a shutdown function.
func initOTLP() func() {
	ctx := context.Background()

	exp, err := otlptracegrpc.New(ctx, otlptracegrpc.WithInsecure())
	if err != nil {
		logrus.WithError(err).Fatal("failed to create exporter")
	}

	bsp := sdktrace.NewBatchSpanProcessor(exp)

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(bsp),
	}

	// If OTEL_SERVICE_NAME name is set, assume the user is using that and
	// OTEL_RESOURCE_ATTRIBUTES to define the resource and use autodiscovery.
	// If it's not set: create the resource manually with a default service name.
	if _, ok := os.LookupEnv("OTEL_SERVICE_NAME"); !ok {
		res, err := resource.New(ctx,
			resource.WithAttributes(
				semconv.ServiceNameKey.String(serviceName),
			),
		)
		if err != nil {
			logrus.WithError(err).Fatal("failed to create resource")
		}
		opts = append(opts, sdktrace.WithResource(res))
	}

	tracerProvider := sdktrace.NewTracerProvider(opts...)

	// Set global propagator to tracecontext (the default is no-op).
	otel.SetTextMapPropagator(propagation.TraceContext{})
	otel.SetTracerProvider(tracerProvider)

	return func() {
		if err = tracerProvider.Shutdown(ctx); err != nil {
			logrus.WithError(err).Fatal("failed to shutdown provider")
		}
		if err = exp.Shutdown(ctx); err != nil {
			logrus.WithError(err).Fatal("failed to stop exporter")
		}
	}
}

// convertTraceID converts the OpenTelemetry TraceID and SpanID (a 128-bit
// unsigned int and 64-bit unsigned int represented as a 32-hex-character and
// 16-hex-character lowercase string, respectively) into their Datadog formats
// (both a 64-bit unsigned int).
//
// Source:
// https://docs.datadoghq.com/tracing/connect_logs_and_traces/opentelemetry/
func convertTraceID(id string) string {
	if len(id) < 16 {
		return ""
	}
	if len(id) > 16 {
		id = id[16:]
	}
	intValue, err := strconv.ParseUint(id, 16, 64)
	if err != nil {
		return ""
	}
	return strconv.FormatUint(intValue, 10)
}
