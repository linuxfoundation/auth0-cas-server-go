# auth0-cas-server-go

## Overview

This service was inspired by Auth0, through their `auth0-cas-server` service
formerly hosted at `github.com/auth0-samples/auth0-cas-server` (link now dead).
Like that service, it uses HTTP redirects to wrap an OpenID Connect
authentication flow with the Central Authentication Service (CAS) SSO protocol,
emulating multiple CAS clients from a single instance of the service. It does
this by using a privileged connection to the Auth0 Management API to find
clients tagged with CAS metadata, and dynamically adopting their client
credentials.

Notable differences include:

- Rewritten in Go, including OpenTelemetry instrumentation and multi-arch build
  outputs including SPDX SBOMs.
- Additional HTTP endpoints to implement additional CAS protocol versions.
- Implements CAS single-logout.
- Implements CAS "gateway mode" to test for authentication without prompting
  the user.
- Supports both XML and JSON CAS response formats.
- Allows for path wildcards and multiple, comma-separated CAS service
  definitions in `client_metadata.cas_service` configuration.

## Linux Foundation specific changes

The following hardcoded behavior is specific to the Linux Foundation's Auth0
environment:

- LF-namespaced OIDC claims used for username and group attributes coming from
  IdP.
- Custom CAS attributes: `uid`, `field_lf_*` and `profile_name_*` added to
  match our reference implementation.

Porting these into a dynamic configuration system would be useful for
generalizing this tool. For instance, a toml file could map upstream OIDC
claims to both required CAS fields as well as optional additional CAS
attributes, and provide per-attribute customization of the mb4-filtering
feature.

## Deploying and running the server

You can pull the latest image from the GitHub Container Registry:

```bash
docker pull ghcr.io/linuxfoundation/auth0-cas-server-go:latest
```

Pinning your deployments to a release label (rather than ":latest") is
recommended for production use.

Please see `env-example` for a list of required and optional environment
variables that can be used to configure the server. For local development, you
can copy this file to `.env` and modify it to suit your needs.

## Auth0 API client configuration

This service requires a non-interactive (machine-to-machine) client that
supports the `client_credentials` grant type and is authorized for the
following scopes on the Auth0 Management API:

- `read:clients`
- `read:client_keys`

The client ID and client secret for this API client must be passed as
environmental variables to the service.

## Auth0 CAS client configuration

To create a CAS-enabled Auth0 application, specify the follow settings:

- Application Type: Regular Web Application
- Allowed Callback URLs: `https://<auth0-cas-server-go>/cas/oidc_callback`
- Allowed Logout URLs (optional): the CAS logout return URL of your
  application, if passed by the CAS client ("service" for v3 logout, or "url"
  for v2 logout).
- Advanced -> Application Metadata: add Key "cas\_service" with Value of
  one-or-more (comma-separated) URLs which match the "service" parameter of the
  CAS application's login request. A `*` will match any subdomain or a single
  path component, while `**` matches anything (including `/`).
- Advanced -> OAuth -> OIDC Conformant: Enabled

Multiple apps CAS can be created for different sites: each will have the same
callback URL, but they will have different `cas_service` URLs (and logout URLs,
if needed).

Auth0 client configurations read by this service are cached for performance.
New apps should work automatically, but changes to `cas_service` URL patterns
for existing apps may require a restart of the service to take effect.

## License

Copyright The Linux Foundation and its contributors.

This project's source code is licensed under the MIT License. A copy of the
license is available in LICENSE.

This project's documentation is licensed under the Creative Commons Attribution
4.0 International License (CC-BY-4.0). A copy of the license is available in
LICENSE-docs.
