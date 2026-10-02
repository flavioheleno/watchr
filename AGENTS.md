# Agent Instructions

This document provides guidance for AI agents working on this Go CLI tool project.

## Project Overview

This is a CLI tool written in Go that uses:

- **cobra** - CLI framework
- **log/slog** - Structured logging

The canonical module path is `github.com/flavioheleno/watchr`. The minimum Go version is declared in `go.mod`; keep README requirements consistent with it.

## Project Structure

Follow the **standard Go layout**:

- `cmd/watchr/` - Application entry point and signal cancellation
- `internal/cmd/` - Cobra commands and thin command handlers
- `internal/dns/`, `internal/http/`, `internal/rdap/`, `internal/tls/`, `internal/whois/` - Network clients and types
- `internal/output/` - Text and JSON formatting
- Add `pkg/` only when a public library package is needed
- Tests alongside implementation files (`*_test.go`)

## Development Workflow

### Test-Driven Development (TDD)

**REQUIRED**: Always write tests before implementation.

1. Write failing test first
2. Implement minimal code to pass the test
3. Refactor if needed
4. Repeat

### Task Management

**Create a todo list** when working on complex tasks to track progress and remain on track.

For multi-step features or refactoring:

1. Break down the task into smaller, actionable items
2. Track progress as you complete each item
3. Update the list when discovering new subtasks
4. Mark items complete immediately after finishing them

This helps maintain focus, prevents missed steps, and provides visibility into progress.

### Code Quality

Always run before committing:

- `gofmt` - Format all Go code
- `go vet ./...` - Static analysis
- `golangci-lint run ./...` - Comprehensive linting
- `go test -race ./...` - Tests with race detection

`make check` runs formatting, vet, lint, and ordinary tests. Run the race-enabled tests separately to match the pull request workflow. Tests use local fixtures and need loopback socket access, not public network access.

## Code Style

### Comments

**Minimal approach**: Only comment complex logic. Prefer self-documenting code with clear variable and function names.

### Error Handling

Use **standard Go idioms**:

```go
result, err := doSomething()
if err != nil {
    return err
}
```

Avoid:

- Wrapped errors (fmt.Errorf with %w) unless specifically needed
- Custom error types unless specifically needed
- Panic for normal error conditions

### Dependencies

**Use proven libraries** when they provide clear benefits. The project already uses cobra and slog - continue using these where appropriate.

When considering new dependencies:

- Prefer well-maintained, widely-used libraries
- Check recent activity and community support
- Evaluate if the benefit justifies the dependency

## Priorities

When making changes, prioritize in this order:

1. **Correctness** - Code must be correct and handle edge cases
2. **Simplicity** - Keep code simple and maintainable
3. **Idiomatic Go** - Follow Go best practices and conventions

## Frameworks Usage

### Cobra (CLI)

- Define commands in `internal/cmd/`; keep startup and signal handling in `cmd/watchr/`
- Use cobra for command structure and flag parsing
- Keep command handlers thin, delegate to internal packages
- Create fresh command trees with `NewRootCommand()` instead of global commands
- Propagate `cmd.Context()` to clients so cancellation reaches network operations
- Keep README command flags, defaults, and output behavior aligned with command help

### Slog (Logging)

- Use structured logging with `log/slog`
- Include relevant context in log entries
- Use appropriate log levels (Debug, Info, Warn, Error)

## Testing

- Write table-driven tests when testing multiple cases
- Use `testing.T` for unit tests
- Mock external dependencies
- Use local HTTP/TLS/DNS/WHOIS fixtures; do not depend on live public services
- Test error conditions and edge cases
- Test cancellation, timeouts, and repeated output values where applicable
- Aim for meaningful test coverage of critical paths

## Anti-Patterns to Avoid

- Global mutable state
- Init functions for complex logic
- Ignoring errors (`_` assignment without good reason)
- Over-engineering simple solutions
- Premature optimization
