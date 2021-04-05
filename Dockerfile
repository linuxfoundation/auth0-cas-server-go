FROM golang:1.16-alpine AS builder

# Set necessary environmet variables needed for our image
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# Add an unprivileged user/group inside the container
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Move to working directory /build
WORKDIR /build

# Download dependencies to go modules cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the code into the container
COPY . .

# Build the packages
RUN go build -o /go/bin/auth0-cas-server-go -ldflags="-w -s" gitlab.com/linuxfoundation/auth0/auth0-cas-server-go

# Run our go binary standalone
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/group /etc/
COPY --from=builder /go/bin/auth0-cas-server-go /go/bin/auth0-cas-server-go

USER appuser:appgroup

# Command to run
ENTRYPOINT ["/go/bin/auth0-cas-server-go"]
