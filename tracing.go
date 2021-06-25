package main

import (
	"context"
	"strconv"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
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
func initOTLP(serviceName string) func() {
	ctx := context.Background()

	exp, err := otlptracegrpc.New(ctx, otlptracegrpc.WithInsecure())
	if err != nil {
		logrus.WithError(err).Fatal("failed to create exporter")
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		logrus.WithError(err).Fatal("failed to create resource")
	}

	bsp := sdktrace.NewBatchSpanProcessor(exp)
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
	)

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
