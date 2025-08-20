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
