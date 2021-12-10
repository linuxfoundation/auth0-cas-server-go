FROM --platform=$BUILDPLATFORM golang:1.16-alpine AS builder

# Set necessary environment variables needed for our image. Allow building to
# other architectures via cross-compliation build-arg.
ARG OTEL_CONTRIB_COLLECTOR_VERSION=v0.40.0
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH

# Move to working directory /build
WORKDIR /build

# Add an unprivileged user/group inside the container
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Download dependencies to go modules cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the code into the container
COPY . .

# Build the packages
RUN go build -o /go/bin/auth0-cas-server-go -ldflags="-w -s" gitlab.com/linuxfoundation/auth0/auth0-cas-server-go

# Bundle otel-collector into package since there is no arm64 Docker package for it.
RUN wget -q -O /go/bin/otelcontribcol "https://github.com/open-telemetry/opentelemetry-collector-contrib/releases/download/${OTEL_CONTRIB_COLLECTOR_VERSION}/otelcontribcol_linux_${TARGETARCH}"
RUN chmod 755 /go/bin/otelcontribcol

# Run our go binary standalone
FROM scratch

EXPOSE 8080
VOLUME ["/etc/otel"]

COPY --from=builder /etc/passwd /etc/group /etc/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy otel-collector config so we can share with otel-collector ECS container
# using a bind mount.
COPY otel_collector_config.yaml /etc/otel/config.yaml

COPY --from=builder /go/bin/auth0-cas-server-go /auth0-cas-server-go
COPY --from=builder /go/bin/otelcontribcol /otelcontribcol

USER appuser:appgroup

# By default, run the CAS server. To run the OTEL agent as a container sidecar,
# override with "/otelcontribcol --config /etc/otel/config.yaml".
ENTRYPOINT ["/auth0-cas-server-go", "-p=8080"]
