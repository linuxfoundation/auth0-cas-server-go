# AGENTS.md

## Build/Test Commands
- `make` or `make bin/auth0-cas-server-go` - Build binary
- `make all` - Build binary and Docker container
- `make lint` - Run mega-linter with Go linting rules
- `make docker-build` - Build Docker container
- `go run .` - Run directly with Go

## Code Style Guidelines
- **License Header**: All files must start with Linux Foundation MIT license header
- **Package**: Single `main` package for this service
- **Imports**: Standard library first, then third-party, separated by blank lines
- **Naming**: Use camelCase for private, PascalCase for public; descriptive variable names
- **Error Handling**: Use slog for logging with structured fields; fatal errors use `slog.Error` with `os.Exit(1)`
- **Comments**: Spell-checker disable/enable blocks around imports; function comments for public APIs
- **Global Variables**: Minimal use (cfg for config, store for sessions)
- **Context**: Pass context through request handlers for logging and tracing
- **Types**: Define custom types for constants (e.g., `contextID int`)
- **Environment**: Use godotenv for optional .env file loading in init()
- **Linting**: Uses mega-linter with revive (not golangci-lint), excludes spell/link checkers

## Key Patterns
- Global config in `cfg` variable populated via init()
- Request-scoped logging with context injection
- OpenTelemetry instrumentation throughout
- Gorilla sessions for cookie management

## Go Toolchain Version

Freely bump `go.mod`'s `go` directive to the latest available *patch*
release (e.g. `1.X.Y` → `1.X.{Y+1}`) to pick up security fixes. Do **not**
bump the *minor* version (e.g. `1.X.x` → `1.{X+1}.x`) unless the user
explicitly asks for it, **and** you've validated it against the Go version
MegaLinter itself bundles -- MegaLinter's `golangci-lint` binary is
statically compiled against a specific Go version and refuses to analyze a
module whose `go.mod` directive is newer than that. (This is a property of
`golangci-lint` itself, not of MegaLinter's `osv-scanner`/`trivy`-based
`REPOSITORY_OSV_SCANNER` check, which is a separate, unrelated linter.) A
`go.mod` directive newer than what `golangci-lint` was built with breaks it
outright. This is a hard ceiling with no environment-variable workaround --
`GOTOOLCHAIN: auto` only affects invocations of the `go` command itself
and does nothing for this precompiled binary's own internal version
checks.

Also be careful with `go get -u`/`go mod tidy`: an indirect dependency
bump can silently drag `go.mod`'s `go` directive forward with it if that
dependency's own `go.mod` requires a newer Go version. Check
`git diff -- go.mod` after any dependency refresh and revert/pin the
offending dependency to an older compatible release if it pulled the
directive past the validated ceiling.
