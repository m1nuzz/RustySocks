# RustySocks

This project implements a simple local SOCKS5 proxy written in Rust using the Tokio asynchronous runtime. It supports SOCKS5 handshake, authentication with an upstream SOCKS5 proxy, and bidirectional data forwarding.

## Features

*   **SOCKS5 Protocol Support**: Handles basic SOCKS5 handshake (no authentication locally).
*   **Upstream Proxy Authentication**: Supports username/password authentication for the upstream SOCKS5 server.
*   **Bidirectional Data Forwarding**: Efficiently relays data between the client and the upstream server.
*   **Robust Error Handling**: Catches and logs network-related errors gracefully, preventing application crashes.

## Requirements

*   Rust (2024 edition)
*   Cargo (Rust's package manager)
*   A `.env` file for configuration (see below)

## Installation and Running

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/your-username/LocalSOCKS5Proxy.git
    cd LocalSOCKS5Proxy
    ```
2.  **Create `.env` file**: Create a file named `.env` in the project root with the following content. Replace the placeholder values with your actual upstream proxy details.

    ```
    LOCAL_ADDR=127.0.0.1:9053
    UPSTREAM_HOST=your_upstream_proxy_ip_or_hostname
    UPSTREAM_PORT=your_upstream_proxy_port
    UPSTREAM_USER=your_upstream_proxy_username
    UPSTREAM_PASS=your_upstream_proxy_password
    ```

3.  **Build and Run**:
    ```bash
    cargo run
    ```

## Configuration

The proxy's configuration is loaded from a `.env` file in the project root. Ensure you set the following environment variables:

*   `LOCAL_ADDR`: The address and port your local SOCKS5 proxy will listen on (e.g., `127.0.0.1:9053`).
*   `UPSTREAM_HOST`: The IP address or hostname of your upstream SOCKS5 proxy.
*   `UPSTREAM_PORT`: The port of your upstream SOCKS5 proxy.
*   `UPSTREAM_USER`: The username for authenticating with the upstream SOCKS5 proxy.
*   `UPSTREAM_PASS`: The password for authenticating with the upstream SOCKS5 proxy.

## Usage

Once running, the proxy will listen on the `LOCAL_ADDR` specified in your `.env` file. Configure your applications (e.g., web browsers, other proxy clients) to use `127.0.0.1:9053` (or whatever `LOCAL_ADDR` you set) as a SOCKS5 proxy.

### Logging

By default, the proxy runs silently without printing logs to the console. To enable detailed logging, run the application with the `--log` flag:

```bash
cargo run -- --log
```
This will print `INFO` and `ERROR` level messages to your console, providing insights into client connections, data forwarding, and any encountered errors.

## Error Handling

The proxy is designed with robust error handling. Network-related issues (e.g., client disconnections, upstream server failures, connection timeouts) are caught and logged without crashing the application, ensuring continuous operation.
