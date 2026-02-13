# watchr

A modern CLI tool for retrieving domain registration details, TLS certificate information, HTTP responses, and DNS records.

[![Go Version](https://img.shields.io/badge/Go-1.25.4-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

## Features

- **Domain Information** - Query RDAP/WHOIS data for domain registration details
- **TLS Certificate Inspection** - Retrieve and analyze TLS certificate chains
- **HTTP Response Analysis** - Fetch HTTP headers and response information
- **DNS Lookups** - Query DNS records for domains
- **Multiple Output Formats** - Text and JSON output support
- **Structured Logging** - Built-in verbose mode for debugging

## Installation

### From Source

```bash
git clone https://github.com/flavioheleno/watchr.git
cd watchr
make build
```

The binary will be available in `./bin/watchr`

### Using Go Install

```bash
go install github.com/flavioheleno/watchr/cmd/watchr@latest
```

## Usage

### Basic Commands

```bash
# Get domain registration information
watchr domain example.com

# Inspect TLS certificate chain
watchr tls example.com

# Fetch HTTP response details
watchr http https://example.com

# Query DNS records
watchr dns example.com
```

### Global Flags

- `-f, --format` - Output format: `text` or `json` (default: text)
- `-t, --timeout` - Request timeout in seconds (default: 10)
- `-v, --verbose` - Enable verbose logging

### Examples

```bash
# Get domain info in JSON format
watchr domain -f json example.com

# Check TLS with increased timeout
watchr tls -t 30 example.com

# HTTP request with verbose logging
watchr http -v https://api.example.com
```

## Development

### Prerequisites

- Go 1.25.4 or later
- Make (optional, for using Makefile commands)

### Building

```bash
# Build the application
make build

# Run tests
make test

# Run tests with coverage
make test-cover

# Format code
make fmt

# Run linter
make lint

# Run all checks
make check
```

### Project Structure

```
watchr/
├── cmd/
│   └── watchr/        # Main application entry point
├── internal/
│   ├── cmd/           # Command implementations
│   ├── dns/           # DNS client and types
│   ├── rdap/          # RDAP client and types
│   ├── output/        # Output formatters
│   └── ...
├── bin/               # Compiled binaries
├── Makefile           # Build automation
└── go.mod             # Go module definition
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/dns/
```

### Development Workflow

This project follows Test-Driven Development (TDD):

1. Write failing test first
2. Implement minimal code to pass
3. Refactor as needed
4. Ensure all checks pass: `make check`

See [AGENTS.md](AGENTS.md) for detailed development guidelines.

## Dependencies

- [cobra](https://github.com/spf13/cobra) - CLI framework
- [whois](https://github.com/likexian/whois) - WHOIS client
- [whois-parser](https://github.com/likexian/whois-parser) - WHOIS data parser
- [dns](https://github.com/miekg/dns) - DNS library
- [rdap](https://github.com/registrobr/rdap) - RDAP client

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`make test`)
5. Run code quality checks (`make check`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

Built with Go and powered by excellent open-source libraries from the Go community.
