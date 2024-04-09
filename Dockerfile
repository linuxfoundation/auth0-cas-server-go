# Copyright The Linux Foundation and its contributors.
# SPDX-License-Identifier: MIT

FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go:latest AS builder

# Set necessary environment variables needed for our image. Allow building to
# other architectures via cross-compliation build-arg.
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH

# Move to working directory /build
WORKDIR /build

# Download dependencies to go modules cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the code into the container
COPY . .

# Build the packages
RUN go build -o /go/bin/auth0-cas-server-go -trimpath -ldflags="-w -s" github.com/linuxfoundation/auth0-cas-server-go

# Run our go binary standalone
FROM cgr.dev/chainguard/static:latest

EXPOSE 8080

COPY --from=builder /go/bin/auth0-cas-server-go /auth0-cas-server-go

ENTRYPOINT ["/auth0-cas-server-go", "-p=8080"]
