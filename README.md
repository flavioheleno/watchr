# watchr

A Go CLI for inspecting domain registration, DNS records, HTTP responses, and TLS certificates and protocol support.

[![Go Version](https://img.shields.io/badge/Go-1.26.0-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Pull Request Checks](https://github.com/flavioheleno/watchr/actions/workflows/pr.yml/badge.svg)](https://github.com/flavioheleno/watchr/actions/workflows/pr.yml)

## Features

- **Domain Information** - Query RDAP/WHOIS data for domain registration details
- **TLS Certificate Inspection** - Retrieve and analyze TLS certificate chains
- **TLS Protocol and Cipher Probing** - Check TLS 1.0–1.3 support and Go-supported TLS 1.0–1.2 cipher suites
- **HTTP Response Analysis** - Inspect status, repeated headers, redirects, and optional request timings
- **DNS Lookups** - Query common record types with custom IPv4 or IPv6 nameservers and TCP fallback
- **Multiple Output Formats** - Text and JSON output support
- **Structured Logging** - Built-in verbose mode for debugging

HTTP and TLS inspection skip certificate verification. Read [Security and scan limitations](#security-and-scan-limitations) before interpreting results.

## Installation

The current source requires Go 1.26.0 or later, as specified in [go.mod](go.mod). Requirements for tagged releases may differ.

### From Source

```bash
git clone https://github.com/flavioheleno/watchr.git
cd watchr
make build
./bin/watchr --help
```

The binary is available in `./bin/watchr`. Use that path directly, or place the binary on your `PATH` to run the `watchr` examples below. Without Make, build with:

```bash
go build -o ./bin/watchr ./cmd/watchr
```

### Using Go Install

```bash
go install github.com/flavioheleno/watchr/cmd/watchr@main
```

`@main` installs the development branch. Older tags, including `v1.0.3`, declare the module as `watchr` rather than `github.com/flavioheleno/watchr`; `@latest` fails when it selects one of those tags. Use `@main` or build from source until a tag with the corrected module path is published, then use `@latest` for the latest tagged release.

Ensure `GOBIN` (or `$(go env GOPATH)/bin` when `GOBIN` is unset) is on your `PATH`.

### Release Binaries

The release workflow builds Linux binaries for amd64, arm64, ARMv7, and ARMv6, compresses them with UPX, and attaches them to [GitHub Releases](https://github.com/flavioheleno/watchr/releases).

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

# Show help for a command
watchr tls --help
```

Each lookup command accepts exactly one positional argument. Use a domain name for `domain` and `dns`, a URL including `http://` or `https://` for `http`, and a hostname or IP address without a scheme or port for `tls`.

### Global Flags

- `-f, --format` - Output format: `text` or `json` (default: text)
- `-t, --timeout` - Positive request timeout in seconds (default: 10)
- `-v, --verbose` - Enable verbose logging
- `-h, --help` - Show command help

Unsupported formats, nonpositive timeouts, and timeout values that overflow Go's duration range are rejected before network requests begin.

Results go to standard output; structured logs and errors go to standard error. JSON can therefore be redirected without mixing in log messages:

```bash
watchr domain -f json example.com > domain.json
```

### Domain Registration

```bash
watchr domain example.com
watchr domain --format json --verbose example.com
```

Queries RDAP first, using IANA bootstrap discovery to locate the registration server. If RDAP fails, the command falls back to WHOIS. Cancellation stops the command without starting a WHOIS fallback.

### DNS Records

- `-T, --type` - Record type, default `A`; accepts `A`, `AAAA`, `MX`, `NS`, `CNAME`, `TXT`, `SOA`, `SRV`, `PTR`, and `CAA`, case-insensitively
- `-s, --server` - Nameserver hostname or IP address, optionally with a port; default port is `53`

```bash
watchr dns --type MX example.com
watchr dns --type TXT --server 8.8.8.8 example.com

# Query a DNS server listening locally on a custom port
watchr dns --server 127.0.0.1:5353 example.com
watchr dns --server '[::1]:5353' --type AAAA example.com

# PTR queries require a reverse-DNS name, not a bare IP address
watchr dns --type PTR 1.0.0.127.in-addr.arpa
```

Bare IPv6 server addresses use port `53`; bracket IPv6 addresses when supplying a custom port. Without `--server`, watchr uses the first nameserver in `/etc/resolv.conf`. If that configuration cannot be read or contains no servers, it warns and falls back to `8.8.8.8`; use `--server` to avoid that public fallback.

Queries start over UDP and retry truncated replies over TCP within the same timeout. Non-success DNS response codes, including `NXDOMAIN`, `SERVFAIL`, and `REFUSED`, are errors. A successful response with no answers is not an error. TXT chunks within each record are joined into one value.

### HTTP Responses

- `-L, --follow-redirects` - Follow redirects; disabled by default
- `--timings` - Include DNS lookup, TCP connection, TLS handshake, server processing, content transfer, and total timings

```bash
watchr http https://example.com
watchr http --follow-redirects --timings https://example.com
watchr http -f json -L --timings https://example.com > response.json
```

Uses GET and reads and discards the response body; it does not print page content. Without `--follow-redirects`, a redirect's status and headers are returned directly. With redirects enabled, the result includes the final URL and redirect chain; the tenth redirect attempt is rejected.

The reported duration includes reading the response body. Timing phases may be zero when a phase does not occur, and their sum need not equal total duration.

### TLS Certificates and Scans

- `-p, --port` - TCP port, default `443`
- `--scan-protocols` - Probe TLS 1.0, 1.1, 1.2, and 1.3 support
- `--scan-ciphers` - Probe protocols and enumerate Go-supported TLS 1.0–1.2 cipher suites
- `--full-scan` - Run protocol and cipher probing with deprecated-protocol warnings

```bash
watchr tls --timeout 30 example.com
watchr tls --port 8443 example.com
watchr tls --scan-protocols example.com
watchr tls --scan-ciphers example.com
watchr tls --full-scan --format json example.com > tls-scan.json
```

Without scan flags, the command reports the negotiated protocol and cipher plus the server-supplied certificate chain, including subjects, issuers, validity dates, public-key algorithms and sizes, and DNS names. Scan flags select scan output instead of certificate output. Currently, `--scan-ciphers` and `--full-scan` perform the same protocol, cipher, and warning checks.

### Timeouts, Cancellation, and Exit Status

`--timeout` is not a single deadline for every command:

- HTTP requests share a timeout across redirects and reading the body.
- DNS queries share a timeout across UDP and any TCP retry.
- TLS certificate retrieval bounds the connection and handshake together; scans apply the timeout to each probe.
- Domain lookups can involve multiple RDAP requests and a WHOIS fallback with separately timed network operations.

Consequently, a scan or domain lookup can take longer than the configured timeout. Ctrl+C (`SIGINT`) and `SIGTERM` cancel the active command.

The CLI exits with `0` when the command succeeds and `1` on an error. HTTP 4xx/5xx responses and TLS warnings alone do not produce a nonzero exit status; inspect the returned status and scan results in scripts.

### Shell Completion

```bash
watchr completion bash --help
watchr completion zsh --help
watchr completion fish --help
watchr completion powershell --help
```

Use the selected shell's help output for generation and installation instructions.

## JSON Output

Use `--format json` for indented JSON. watchr's own multiword field names use camelCase; parsed WHOIS data retains the parser library's snake_case names. Duration fields such as HTTP `duration`, DNS `queryTime`, and every HTTP `timings` value are integer nanoseconds; certificate and RDAP event dates use RFC 3339 timestamps.

HTTP `headers` maps each header name to an array of values, even when only one value exists. Repeated `Set-Cookie` values are preserved independently. Text output prints each header value on its own line. For example, an illustrative HTTP result is:

```json
{
  "url": "https://example.com",
  "statusCode": 200,
  "status": "200 OK",
  "headers": {
    "Content-Type": ["text/html"],
    "Set-Cookie": ["session=abc; HttpOnly", "theme=dark"]
  },
  "contentLength": 1256,
  "duration": 120000000
}
```

HTTP `contentLength` is a number when known, otherwise `"chunked"` or `"unknown"`. `timings`, HTTPS TLS details, and `redirectChain` appear only when applicable.

RDAP results contain registration fields directly. WHOIS fallback results use a different shape: `source: "WHOIS"` with `raw` and `parsed` when parsing succeeds, or `source: "WHOIS"` with `data` when it does not. Scripts should account for both sources.

TLS scan output includes `supportedVersions` and `scanLimitations`. Cipher scans also include `cipherSuites` for TLS 1.0–1.2 when supported; TLS 1.3 is not included in that map. If TLS 1.3 succeeds, its single negotiated cipher is reported separately as `negotiatedTLS13Cipher`. Optional fields such as `vulnerabilities`, `preferredVersion`, and `preferredCipher` are omitted when empty.

## Security and Scan Limitations

- HTTPS requests made by `watchr http`, TLS certificate inspection, and TLS scan probes skip certificate chain and hostname verification. This permits inspecting self-signed or expired certificates, but a successful command does not establish server identity or certificate trust. Expiry warnings are informational.
- Protocol and cipher probes are limited to the Go toolchain's `crypto/tls` capabilities, including Go-supported insecure cipher suites for older protocol versions. A failed handshake does not prove that a server lacks support for every possible client configuration.
- TLS 1.3 cipher suites cannot be individually configured for enumeration by this scanner. The reported TLS 1.3 cipher is one negotiated result, not an exhaustive list.
- `preferredVersion` is the highest successfully probed version; `preferredCipher` is a cipher negotiated in a successful probe, not an exhaustive ranking of server preferences.
- Scan warnings flag TLS 1.0/1.1 support and the absence of TLS 1.2/1.3. They are not a comprehensive vulnerability audit, and an empty warning list does not prove that a server is secure.

Only scan systems you are authorized to test.

## Development

### Prerequisites

- Go 1.26.0 or later
- Make (optional, for using Makefile commands)
- [golangci-lint](https://golangci-lint.run/docs/welcome/install/) on `PATH` for `make lint` and `make check`; use a release that supports your Go toolchain

### Building and Checks

```bash
# Build the application into ./bin/watchr
make build

# Run tests (without the race detector)
make test

# Run race-enabled tests and generate coverage.out and coverage.html
make test-cover

# Format code, run vet, lint, and tests
make check

# Download or tidy and verify dependencies
make deps
make tidy
```

Checks without Make, including the race detector:

```bash
go fmt ./...
go vet ./...
golangci-lint run ./...
go test -race ./...
go build -o ./bin/watchr ./cmd/watchr
```

`make check` uses ordinary tests; run `go test -race ./...` as well to match CI's race-detector coverage.

### Project Structure

```
watchr/
├── cmd/
│   └── watchr/        # CLI entry point and signal cancellation
├── internal/
│   ├── cmd/           # Cobra commands and CLI tests
│   ├── dns/           # DNS client and types
│   ├── http/          # HTTP client, timing capture, and types
│   ├── output/        # Text and JSON formatters
│   ├── rdap/          # RDAP client and types
│   ├── tls/           # Certificate client and protocol/cipher scanner
│   └── whois/         # WHOIS client
├── .github/           # PR/release workflows and Dependabot configuration
├── bin/               # Local build output (ignored by Git)
├── AGENTS.md          # Development guidance for agents
├── Makefile           # Build automation
└── go.mod             # Go module definition
```

### Running Tests

```bash
# Run all tests
go test -race ./...

# Run tests with coverage
go test -race -cover ./...

# Run specific package tests
go test -race ./internal/dns
```

Tests use local HTTP/TLS/DNS/WHOIS fixtures and mocked registration queries, not public network services. They require permission to bind loopback sockets. Dependencies must already be downloaded for offline runs.

### Development Workflow

This project follows Test-Driven Development (TDD):

1. Write failing test first
2. Implement minimal code to pass
3. Refactor as needed
4. Run `make check` and `go test -race ./...` before committing

See [AGENTS.md](AGENTS.md) for detailed development guidelines.

### Continuous Integration and Releases

Pull requests run formatting checks, `go vet`, `golangci-lint`, race-enabled tests, and a build. The Go version comes from `go.mod`.

Pushing a tag matching `v*.*.*` triggers the release workflow: build the four Linux targets with CGO disabled, compress them with UPX, and upload them to a GitHub release. Workflow actions are pinned to commit SHAs. Dependabot checks Go modules and GitHub Actions weekly.

## Dependencies

- [cobra](https://github.com/spf13/cobra) - CLI framework
- [whois](https://github.com/likexian/whois) - WHOIS client
- [whois-parser](https://github.com/likexian/whois-parser) - WHOIS data parser
- [dns](https://github.com/miekg/dns) - DNS library
- [rdap](https://github.com/registrobr/rdap) - RDAP client

Exact direct and indirect dependency versions are recorded in [go.mod](go.mod), with checksums in [go.sum](go.sum).

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Run race-enabled tests (`go test -race ./...`)
5. Run code quality checks (`make check`)
6. Make focused commits describing one logical change each
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

Built with Go and powered by excellent open-source libraries from the Go community.
