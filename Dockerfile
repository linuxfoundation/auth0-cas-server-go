FROM --platform=$BUILDPLATFORM golang:1.19-alpine AS builder

# Set necessary environment variables needed for our image. Allow building to
# other architectures via cross-compliation build-arg.
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
RUN go build -o /go/bin/auth0-cas-server-go -trimpath -ldflags="-w -s" gitlab.com/linuxfoundation/auth0/auth0-cas-server-go

# Run our go binary standalone
FROM scratch

EXPOSE 8080

COPY --from=builder /etc/passwd /etc/group /etc/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /go/bin/auth0-cas-server-go /auth0-cas-server-go

USER appuser:appgroup

ENTRYPOINT ["/auth0-cas-server-go", "-p=8080"]
