# RustySocks

RustySocks is a small asynchronous SOCKS5 proxy written in Rust with Tokio. It listens on a local address, accepts SOCKS5 clients without local authentication, and forwards TCP and UDP traffic through an upstream SOCKS5 proxy using username/password authentication.

## Features

- **SOCKS5 protocol support**: Handles the SOCKS5 greeting and request handshake (no authentication required locally).
- **TCP CONNECT relay**: Forwards client TCP connections through an upstream SOCKS5 proxy.
- **Upstream proxy authentication**: Supports username/password authentication for the upstream SOCKS5 server.
- **UDP ASSOCIATE relay**: Performs UDP ASSOCIATE through the upstream SOCKS5 proxy and relays UDP packets.
- **Graceful shutdown**: Stops cleanly on `Ctrl-C` and, on Unix, `SIGTERM`.
- **Configurable timeouts**: Upstream connection timeout is configurable.
- **Credential validation**: Upstream username and password are limited to 255 bytes.
- **Structured logging**: Optional console logging via `--log` and `-v`/`-vv`/`-vvv`.
- **Cross-platform builds**: CI builds release binaries for Linux, Windows, and macOS.

## Requirements

- Rust (2024 edition) and Cargo
- A `.env` file in the project root (see [Configuration](#configuration))

## Installation and running

1. Clone the repository:

   ```bash
   git clone https://github.com/m1nuzz/RustySocks.git
   cd RustySocks
   ```

2. Create a `.env` file in the project root:

   ```env
   LOCAL_ADDR=127.0.0.1:9053
   UPSTREAM_HOST=your_upstream_proxy_ip_or_hostname
   UPSTREAM_PORT=your_upstream_proxy_port
   UPSTREAM_USER=your_upstream_proxy_username
   UPSTREAM_PASS=your_upstream_proxy_password
   ```

3. Build and run:

   ```bash
   cargo run
   ```

   Enable logging:

   ```bash
   cargo run -- --log
   cargo run -- --log -v
   ```

## Configuration

Configuration is loaded from `.env`. The following variables are supported:

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `LOCAL_ADDR` | No | `127.0.0.1:9053` | Address and port the local SOCKS5 proxy listens on. |
| `UPSTREAM_HOST` | Yes | - | IP address or hostname of the upstream SOCKS5 proxy. |
| `UPSTREAM_PORT` | Yes | - | Port of the upstream SOCKS5 proxy. |
| `UPSTREAM_USER` | Yes | - | Username for upstream proxy authentication. |
| `UPSTREAM_PASS` | Yes | - | Password for upstream proxy authentication. |
| `CONNECT_TIMEOUT` | No | `10` | Upstream connection timeout in seconds. |
| `CLIENT_READ_TIMEOUT` | No | `30` | Timeout for reading from SOCKS5 clients in seconds. |

Notes:

- `.env` is ignored by Git. Do not commit real credentials.
- `UPSTREAM_USER` and `UPSTREAM_PASS` must each be at most 255 bytes.

## Usage

After starting the proxy, configure your application to use `127.0.0.1:9053` (or the value of `LOCAL_ADDR`) as a SOCKS5 proxy.

By default the proxy runs quietly. Use `--log` to print `INFO` and `ERROR` messages, and add `-v`/`-vv`/`-vvv` for more verbosity.

## Development

Format check:

```bash
cargo fmt --all -- --check
```

Lint:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Tests:

```bash
cargo test --all-features
```

Release build:

```bash
cargo build --release
```

Some integration tests require a working upstream proxy and a valid `.env` file. They are marked `#[ignore]` and can be run explicitly:

```bash
cargo test --test real_connection_tests -- --ignored --nocapture
```

## CI/CD

GitHub Actions workflows are included:

- `.github/workflows/ci.yml`: runs rustfmt, Clippy with `-D warnings`, tests, and a release build on pushes and pull requests.
- `.github/workflows/release.yml`: builds release binaries for Linux (GNU and musl), Windows, and macOS on version tags (`v*`) or manual dispatch, uploads artifacts, and creates a GitHub Release.

## Security notes

- Keep `.env` out of version control.
- Upstream credentials are validated for length before use.
- The local SOCKS5 listener does not require authentication; bind it to a trusted interface.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).