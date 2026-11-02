#![cfg_attr(not(test), windows_subsystem = "windows")]
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables, unused_mut))]

use clap::Parser;
use dotenvy::dotenv;
use log::{debug, error, info, warn};
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Failed to get UPSTREAM_HOST from .env: {0}")]
    UpstreamHostEnv(env::VarError),
    #[error("Failed to get UPSTREAM_PORT from .env: {0}")]
    UpstreamPortEnv(env::VarError),
    #[error("Failed to parse UPSTREAM_PORT: {0}")]
    UpstreamPortParse(#[from] std::num::ParseIntError),
    #[error("Failed to get UPSTREAM_USER from .env: {0}")]
    UpstreamUserEnv(env::VarError),
    #[error("Failed to get UPSTREAM_PASS from .env: {0}")]
    UpstreamPassEnv(env::VarError),
    #[error("UPSTREAM_USER or UPSTREAM_PASS is too long (max 255 bytes)")]
    UpstreamCredentialsTooLong,
    #[error("SOCKS handshake failed: invalid format or version")]
    InvalidHandshake,
    #[error("Unsupported SOCKS command: {0:#x}")]
    UnsupportedCommand(u8),
    #[error("Unsupported address type: {0:#x}")]
    UnsupportedAddressType(u8),
    #[error("Failed to connect to upstream {0}: {1}")]
    UpstreamConnectionFailed(String, std::io::Error),
    #[error("Upstream authentication failed")]
    UpstreamAuthFailed,
    #[error("Upstream connection failed with status: {0:#x}")]
    UpstreamConnectionFailedStatus(u8),
    #[error("Unsupported bind address type from upstream: {0:#x}")]
    UnsupportedBindType(u8),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("UDP association failed")]
    UdpAssociationFailed,
    #[error("Invalid UDP packet")]
    InvalidUdpPacket,
}

impl From<env::VarError> for ProxyError {
    fn from(err: env::VarError) -> Self {
        ProxyError::UpstreamHostEnv(err)
    }
}

#[derive(Clone)]
pub struct Config {
    pub local_addr: String,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub upstream_user: String,
    pub upstream_pass: String,
    pub connect_timeout_secs: u64,
    pub client_read_timeout_secs: u64,
}

pub fn get_config() -> Result<Config, ProxyError> {
    if let Ok(exe_path) = env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
    {
        let _ = env::set_current_dir(exe_dir);
    }

    dotenv().ok();

    let upstream_user = env::var("UPSTREAM_USER").map_err(ProxyError::UpstreamUserEnv)?;
    let upstream_pass = env::var("UPSTREAM_PASS").map_err(ProxyError::UpstreamPassEnv)?;
    if upstream_user.len() > 255 || upstream_pass.len() > 255 {
        return Err(ProxyError::UpstreamCredentialsTooLong);
    }

    let config = Config {
        local_addr: env::var("LOCAL_ADDR").unwrap_or_else(|_| "127.0.0.1:9053".to_string()),
        upstream_host: env::var("UPSTREAM_HOST").map_err(ProxyError::UpstreamHostEnv)?,
        upstream_port: env::var("UPSTREAM_PORT")
            .map_err(ProxyError::UpstreamPortEnv)?
            .parse::<u16>()
            .map_err(ProxyError::UpstreamPortParse)?,
        upstream_user,
        upstream_pass,
        connect_timeout_secs: env::var("CONNECT_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10),
        client_read_timeout_secs: env::var("CLIENT_READ_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30),
    };

    Ok(config)
}

/// SOCKS5 Proxy
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Enable logging
    #[arg(short, long)]
    pub log: bool,

    /// Log verbosity (use multiple times for more verbosity, e.g., -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    if args.log {
        let mut builder = env_logger::builder();
        builder.filter_level(log::LevelFilter::Info);

        if args.verbose >= 1 {
            builder.filter_level(log::LevelFilter::Debug);
        }
        if args.verbose >= 2 {
            builder.filter_level(log::LevelFilter::Trace);
        }

        builder.init();
    }

    let config = get_config()?;
    let config = Arc::new(config);
    info!("SOCKS5 Proxy listening on {}", config.local_addr);

    let listener = TcpListener::bind(&config.local_addr).await?;

    // Graceful shutdown signalling (Ctrl-C on all platforms, SIGTERM on Unix).
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    let tx_ctrlc = shutdown_tx.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = tx_ctrlc.send(()).await;
        }
    });
    #[cfg(unix)]
    {
        let tx_term = shutdown_tx.clone();
        if let Ok(mut term_signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::spawn(async move {
                term_signal.recv().await;
                let _ = tx_term.send(()).await;
            });
        }
    }
    drop(shutdown_tx);

    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((client_socket, client_addr)) => {
                        info!("New client connection from {}", client_addr);
                        let config_ref = Arc::clone(&config);
                        tasks.spawn(async move {
                            if let Err(e) = handle_client(client_socket, config_ref).await {
                                error!("Error handling client from {}: {}", client_addr, e);
                            }
                        });
                    }
                    Err(e) => error!("Accept error: {}", e),
                }
            }
        }
    }

    // Drain in-flight client tasks.
    while let Some(res) = tasks.join_next().await {
        if let Err(e) = res {
            warn!("Client task join error: {}", e);
        }
    }

    info!("SOCKS5 Proxy shutting down");
    Ok(())
}

/// Parse SOCKS5 address from stream
async fn parse_socks5_address<T: AsyncReadExt + Unpin>(
    stream: &mut T,
    client_addr: SocketAddr,
) -> Result<(Vec<u8>, String, u16), ProxyError> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;

    let addr_type = head[3];
    let mut dest_info = Vec::new();
    dest_info.extend_from_slice(&head);

    let dest_addr_str: String = match addr_type {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            dest_info.extend_from_slice(&ip);
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        0x03 => {
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            dest_info.push(len_byte[0]);
            let mut domain = vec![0u8; len_byte[0] as usize];
            stream.read_exact(&mut domain).await?;
            dest_info.extend_from_slice(&domain);
            String::from_utf8_lossy(&domain).into_owned()
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            dest_info.extend_from_slice(&ip);
            format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                ip[0],
                ip[1],
                ip[2],
                ip[3],
                ip[4],
                ip[5],
                ip[6],
                ip[7],
                ip[8],
                ip[9],
                ip[10],
                ip[11],
                ip[12],
                ip[13],
                ip[14],
                ip[15]
            )
        }
        _ => {
            error!(
                "Unsupported address type for client {}: {:#x}",
                client_addr, addr_type
            );
            return Err(ProxyError::UnsupportedAddressType(addr_type));
        }
    };

    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    dest_info.extend_from_slice(&port_bytes);
    let dest_port = u16::from_be_bytes(port_bytes);

    Ok((dest_info, dest_addr_str, dest_port))
}

/// Build SOCKS5 address reply
pub fn build_socks5_reply(addr_type: u8, addr: &[u8], port: u16) -> Vec<u8> {
    let mut reply = Vec::with_capacity(4 + addr.len() + 2);
    reply.push(0x05); // Version
    reply.push(0x00); // Success
    reply.push(0x00); // RSV
    reply.push(addr_type); // ATYP
    reply.extend_from_slice(addr);
    reply.extend_from_slice(&port.to_be_bytes());
    reply
}

/// Parse SOCKS5 UDP packet header
pub fn parse_udp_header(data: &[u8]) -> Result<(usize, String, u16), ProxyError> {
    if data.len() < 4 {
        return Err(ProxyError::InvalidUdpPacket);
    }

    // RSV (2 bytes) + FRAG (1 byte) + ATYP (1 byte)
    let frag = data[2];
    if frag != 0 {
        warn!("Fragmented UDP packet received (frag={})", frag);
        // For simplicity, we don't handle fragmentation
    }

    let addr_type = data[3];
    let mut offset = 4;

    let dest_addr: String;
    match addr_type {
        0x01 => {
            // IPv4
            if data.len() < offset + 4 {
                return Err(ProxyError::InvalidUdpPacket);
            }
            let ip = &data[offset..offset + 4];
            dest_addr = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
            offset += 4;
        }
        0x03 => {
            // Domain name
            if data.len() < offset + 1 {
                return Err(ProxyError::InvalidUdpPacket);
            }
            let len = data[offset] as usize;
            offset += 1;
            if data.len() < offset + len {
                return Err(ProxyError::InvalidUdpPacket);
            }
            dest_addr = String::from_utf8_lossy(&data[offset..offset + len]).into_owned();
            offset += len;
        }
        0x04 => {
            // IPv6
            if data.len() < offset + 16 {
                return Err(ProxyError::InvalidUdpPacket);
            }
            let ip = &data[offset..offset + 16];
            dest_addr = format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                ip[0],
                ip[1],
                ip[2],
                ip[3],
                ip[4],
                ip[5],
                ip[6],
                ip[7],
                ip[8],
                ip[9],
                ip[10],
                ip[11],
                ip[12],
                ip[13],
                ip[14],
                ip[15]
            );
            offset += 16;
        }
        _ => {
            return Err(ProxyError::UnsupportedAddressType(addr_type));
        }
    }

    if data.len() < offset + 2 {
        return Err(ProxyError::InvalidUdpPacket);
    }

    let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    Ok((offset, dest_addr, port))
}

/// Build SOCKS5 UDP packet header
pub fn build_udp_header(addr_type: u8, addr: &[u8], port: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(4 + addr.len() + 2);
    header.push(0x00); // RSV
    header.push(0x00); // RSV
    header.push(0x00); // FRAG (no fragmentation)
    header.push(addr_type); // ATYP
    header.extend_from_slice(addr);
    header.extend_from_slice(&port.to_be_bytes());
    header
}

pub async fn handle_client(mut client: TcpStream, config: Arc<Config>) -> Result<(), ProxyError> {
    let client_addr = client.peer_addr()?;
    debug!("Handling client from {}", client_addr);

    // Read client greeting
    let mut buf = [0u8; 262];
    let n = match tokio::time::timeout(
        Duration::from_secs(config.client_read_timeout_secs),
        client.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            return Err(ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "client read timed out",
            )));
        }
    };
    if n < 2 || buf[0] != 0x05 {
        error!(
            "SOCKS handshake failed for client {}: invalid format or version",
            client_addr
        );
        return Err(ProxyError::InvalidHandshake);
    }

    // Reply with no authentication required
    client.write_all(b"\x05\x00").await?;

    // Read request header (VER, CMD, RSV, ATYP)
    let (dest_info, dest_addr_str, dest_port) = match tokio::time::timeout(
        Duration::from_secs(config.client_read_timeout_secs),
        parse_socks5_address(&mut client, client_addr),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "client read timed out",
            )));
        }
    };

    info!(
        "Client {} requested connection to {}:{}",
        client_addr, dest_addr_str, dest_port
    );

    let cmd = dest_info[1];

    match cmd {
        0x01 => {
            // CONNECT command - TCP relay
            handle_tcp_connect(
                client,
                config,
                dest_info,
                dest_addr_str,
                dest_port,
                client_addr,
            )
            .await
        }
        0x03 => {
            // UDP ASSOCIATE command
            handle_udp_associate(client, config, dest_addr_str, dest_port, client_addr).await
        }
        0x02 => {
            // BIND command - proxied through upstream SOCKS5
            handle_bind(
                client,
                config,
                dest_info,
                dest_addr_str,
                dest_port,
                client_addr,
            )
            .await
        }
        _ => {
            error!("Unknown command {:#x} for client {}", cmd, client_addr);
            Err(ProxyError::UnsupportedCommand(cmd))
        }
    }
}

/// Handle TCP CONNECT command
async fn handle_tcp_connect(
    mut client: TcpStream,
    config: Arc<Config>,
    dest_info: Vec<u8>,
    dest_addr_str: String,
    dest_port: u16,
    client_addr: SocketAddr,
) -> Result<(), ProxyError> {
    // Connect to upstream proxy with timeout
    let upstream_addr = format!("{}:{}", config.upstream_host, config.upstream_port);
    let upstream = tokio::time::timeout(
        Duration::from_secs(config.connect_timeout_secs),
        TcpStream::connect(upstream_addr.clone()),
    )
    .await
    .map_err(|_| {
        ProxyError::UpstreamConnectionFailed(
            upstream_addr.clone(),
            std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out"),
        )
    })?
    .map_err(|e| ProxyError::UpstreamConnectionFailed(upstream_addr.clone(), e))?;

    debug!("Connected to upstream {}", upstream.peer_addr()?);

    let mut upstream = upstream;

    // Authenticate with upstream.
    upstream_authenticate(&mut upstream, &config).await?;

    // Send connection request to upstream
    upstream.write_all(&dest_info).await?;

    // Read upstream response header
    let mut upstream_resp_head = [0u8; 4];
    read_exact_timeout(
        &mut upstream,
        &mut upstream_resp_head,
        config.client_read_timeout_secs,
    )
    .await?;

    if upstream_resp_head[1] == 0x00 {
        // Success - read the bound address
        let bind_type = upstream_resp_head[3];
        match bind_type {
            0x01 => {
                let mut b = [0u8; 6];
                read_exact_timeout(&mut upstream, &mut b, config.client_read_timeout_secs).await?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                read_exact_timeout(&mut upstream, &mut len, config.client_read_timeout_secs)
                    .await?;
                let mut domain = vec![0u8; len[0] as usize + 2];
                read_exact_timeout(&mut upstream, &mut domain, config.client_read_timeout_secs)
                    .await?;
            }
            0x04 => {
                let mut b = [0u8; 18];
                read_exact_timeout(&mut upstream, &mut b, config.client_read_timeout_secs).await?;
            }
            _ => {
                error!(
                    "Unsupported bind address type from upstream {}: {:#x}",
                    upstream.peer_addr()?,
                    bind_type
                );
                return Err(ProxyError::UnsupportedBindType(bind_type));
            }
        }

        // Send success response to client
        client
            .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            .await?;
        info!(
            "TCP connection established for client {}, proxying to {}:{}",
            client_addr, dest_addr_str, dest_port
        );

        // Start bidirectional data forwarding
        let (mut ci, mut co) = client.into_split();
        let (mut ui, mut uo) = upstream.into_split();

        let _ = tokio::try_join!(
            tokio::io::copy(&mut ci, &mut uo),
            tokio::io::copy(&mut ui, &mut co)
        )
        .map_err(|e| {
            debug!("Data proxying failed for client {}: {}", client_addr, e);
            e
        })?;
        info!("TCP proxying completed for client {}.", client_addr);
    } else {
        error!(
            "Upstream connection failed for client {} with status: {:#x}",
            client_addr, upstream_resp_head[1]
        );
        return Err(ProxyError::UpstreamConnectionFailedStatus(
            upstream_resp_head[1],
        ));
    }

    Ok(())
}

/// Handle BIND command
async fn handle_bind(
    mut client: TcpStream,
    config: Arc<Config>,
    dest_info: Vec<u8>,
    dest_addr_str: String,
    dest_port: u16,
    client_addr: SocketAddr,
) -> Result<(), ProxyError> {
    info!(
        "BIND request from {} for {}:{}",
        client_addr, dest_addr_str, dest_port
    );

    // Connect to upstream proxy with timeout
    let upstream_addr = format!("{}:{}", config.upstream_host, config.upstream_port);
    let upstream = tokio::time::timeout(
        Duration::from_secs(config.connect_timeout_secs),
        TcpStream::connect(upstream_addr.clone()),
    )
    .await
    .map_err(|_| {
        ProxyError::UpstreamConnectionFailed(
            upstream_addr.clone(),
            std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out"),
        )
    })?
    .map_err(|e| ProxyError::UpstreamConnectionFailed(upstream_addr.clone(), e))?;

    let mut upstream = upstream;

    // Authenticate with upstream.
    upstream_authenticate(&mut upstream, &config).await?;

    // Send BIND request to upstream
    upstream.write_all(&dest_info).await?;

    // Read and forward the first reply (bind result).
    let first_reply = read_socks5_reply(&mut upstream, config.client_read_timeout_secs).await?;
    if first_reply.len() >= 2 && first_reply[1] != 0x00 {
        let _ = client.write_all(&first_reply).await;
        return Err(ProxyError::UpstreamConnectionFailedStatus(first_reply[1]));
    }
    client.write_all(&first_reply).await?;

    // Wait for and forward the second reply (incoming connection).
    let second_timeout = config.client_read_timeout_secs.max(30) * 10;
    let second_reply = read_socks5_reply(&mut upstream, second_timeout).await?;
    if second_reply.len() >= 2 && second_reply[1] != 0x00 {
        let _ = client.write_all(&second_reply).await;
        return Err(ProxyError::UpstreamConnectionFailedStatus(second_reply[1]));
    }
    client.write_all(&second_reply).await?;

    info!("BIND connection established for client {}", client_addr);

    // Start bidirectional data forwarding
    let (mut ci, mut co) = client.into_split();
    let (mut ui, mut uo) = upstream.into_split();

    let _ = tokio::try_join!(
        tokio::io::copy(&mut ci, &mut uo),
        tokio::io::copy(&mut ui, &mut co)
    )
    .map_err(|e| {
        debug!("BIND proxying failed for client {}: {}", client_addr, e);
        e
    })?;
    info!("BIND proxying completed for client {}.", client_addr);

    Ok(())
}

/// Read a full SOCKS5 reply from a stream
async fn read_socks5_reply(
    stream: &mut TcpStream,
    timeout_secs: u64,
) -> Result<Vec<u8>, ProxyError> {
    let mut head = [0u8; 4];
    read_exact_timeout(stream, &mut head, timeout_secs).await?;
    let mut reply = head.to_vec();
    match head[3] {
        0x01 => {
            let mut b = [0u8; 6];
            read_exact_timeout(stream, &mut b, timeout_secs).await?;
            reply.extend_from_slice(&b);
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_exact_timeout(stream, &mut len, timeout_secs).await?;
            reply.push(len[0]);
            let mut domain = vec![0u8; len[0] as usize];
            read_exact_timeout(stream, &mut domain, timeout_secs).await?;
            reply.extend_from_slice(&domain);
            let mut port = [0u8; 2];
            read_exact_timeout(stream, &mut port, timeout_secs).await?;
            reply.extend_from_slice(&port);
        }
        0x04 => {
            let mut b = [0u8; 18];
            read_exact_timeout(stream, &mut b, timeout_secs).await?;
            reply.extend_from_slice(&b);
        }
        t => return Err(ProxyError::UnsupportedBindType(t)),
    }
    Ok(reply)
}

/// Handle UDP ASSOCIATE command
async fn handle_udp_associate(
    mut client: TcpStream,
    config: Arc<Config>,
    _dest_addr_str: String,
    _dest_port: u16,
    client_addr: SocketAddr,
) -> Result<(), ProxyError> {
    info!("UDP ASSOCIATE request from {}", client_addr);

    // Connect to upstream proxy (TCP control connection).
    let upstream_addr = format!("{}:{}", config.upstream_host, config.upstream_port);
    let upstream_tcp = tokio::time::timeout(
        Duration::from_secs(config.connect_timeout_secs),
        TcpStream::connect(&upstream_addr),
    )
    .await
    .map_err(|_| {
        ProxyError::UpstreamConnectionFailed(
            upstream_addr.clone(),
            std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out"),
        )
    })?
    .map_err(|e| ProxyError::UpstreamConnectionFailed(upstream_addr.clone(), e))?;

    let mut upstream_tcp = upstream_tcp;

    // Authenticate with upstream.
    upstream_authenticate(&mut upstream_tcp, &config).await?;

    // Request UDP ASSOCIATE on upstream (bind address 0.0.0.0:0).
    upstream_tcp
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // Read upstream reply.
    let mut resp_head = [0u8; 4];
    read_exact_timeout(
        &mut upstream_tcp,
        &mut resp_head,
        config.client_read_timeout_secs,
    )
    .await?;
    if resp_head[0] != 0x05 {
        return Err(ProxyError::InvalidHandshake);
    }
    if resp_head[1] != 0x00 {
        return Err(ProxyError::UpstreamConnectionFailedStatus(resp_head[1]));
    }
    let bind_type = resp_head[3];
    let (upstream_udp_ip, upstream_udp_port) =
        read_upstream_bound_addr(&mut upstream_tcp, bind_type, &config).await?;
    let upstream_udp_addr = SocketAddr::new(upstream_udp_ip, upstream_udp_port);

    debug!("Upstream UDP association bound to {}", upstream_udp_addr);

    // Bind local UDP socket for the client.
    let local_ip = client.local_addr()?.ip();
    let local_udp = UdpSocket::bind(format!("{}:0", local_ip)).await?;
    let local_udp_addr = local_udp.local_addr()?;

    // Reply to client with local UDP address.
    let reply = if local_udp_addr.ip().is_ipv4() {
        let ip_bytes = match local_udp_addr.ip() {
            std::net::IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            _ => vec![0, 0, 0, 0],
        };
        build_socks5_reply(0x01, &ip_bytes, local_udp_addr.port())
    } else {
        let ip_bytes = match local_udp_addr.ip() {
            std::net::IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
            _ => vec![0; 16],
        };
        build_socks5_reply(0x04, &ip_bytes, local_udp_addr.port())
    };
    client.write_all(&reply).await?;

    info!(
        "UDP association established for client {}, local UDP port: {}, upstream UDP: {}",
        client_addr,
        local_udp_addr.port(),
        upstream_udp_addr
    );

    // Upstream-facing UDP socket.
    let upstream_udp = UdpSocket::bind("0.0.0.0:0").await?;

    let mut client_udp_addr: Option<SocketAddr> = None;
    let mut client_buf = vec![0u8; 65535];
    let mut upstream_buf = vec![0u8; 65535];
    let mut tcp_buf = [0u8; 1];
    let mut upstream_tcp_buf = [0u8; 1];

    let idle_timeout = Duration::from_secs(
        config
            .client_read_timeout_secs
            .max(config.connect_timeout_secs)
            * 10,
    );

    loop {
        tokio::select! {
            res = local_udp.recv_from(&mut client_buf) => {
                let (n, from) = res?;
                client_udp_addr = Some(from);
                // Forward SOCKS5 UDP packet to upstream as-is.
                let _ = upstream_udp.send_to(&client_buf[..n], upstream_udp_addr).await;
                debug!("UDP client->upstream {} bytes", n);
            }
            res = upstream_udp.recv_from(&mut upstream_buf) => {
                let (n, _) = res?;
                if let Some(caddr) = client_udp_addr {
                    let _ = local_udp.send_to(&upstream_buf[..n], caddr).await;
                    debug!("UDP upstream->client {} bytes", n);
                }
            }
            res = client.read(&mut tcp_buf) => {
                let n = res?;
                if n == 0 {
                    debug!("TCP control connection closed for client {}", client_addr);
                    break;
                }
            }
            res = upstream_tcp.read(&mut upstream_tcp_buf) => {
                let n = res?;
                if n == 0 {
                    debug!("Upstream TCP control connection closed for client {}", client_addr);
                    break;
                }
            }
            _ = tokio::time::sleep(idle_timeout) => {
                debug!("UDP association idle timeout for client {}", client_addr);
                break;
            }
        }
    }

    info!("UDP association terminated for client {}", client_addr);
    Ok(())
}

async fn upstream_authenticate(stream: &mut TcpStream, config: &Config) -> Result<(), ProxyError> {
    stream.write_all(b"\x05\x02\x00\x02").await?;

    let mut auth_response = [0u8; 2];
    read_exact_timeout(stream, &mut auth_response, config.client_read_timeout_secs).await?;

    if auth_response[1] == 0x02 {
        let mut auth_packet = Vec::new();
        auth_packet.push(0x01);
        auth_packet.push(config.upstream_user.len() as u8);
        auth_packet.extend_from_slice(config.upstream_user.as_bytes());
        auth_packet.push(config.upstream_pass.len() as u8);
        auth_packet.extend_from_slice(config.upstream_pass.as_bytes());

        stream.write_all(&auth_packet).await?;

        let mut status = [0u8; 2];
        read_exact_timeout(stream, &mut status, config.client_read_timeout_secs).await?;
        if status[1] != 0x00 {
            return Err(ProxyError::UpstreamAuthFailed);
        }
    }

    Ok(())
}

async fn read_exact_timeout(
    stream: &mut TcpStream,
    buf: &mut [u8],
    timeout_secs: u64,
) -> Result<(), ProxyError> {
    match tokio::time::timeout(Duration::from_secs(timeout_secs), stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(ProxyError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "read timed out",
        ))),
    }
}

async fn read_upstream_bound_addr(
    stream: &mut TcpStream,
    addr_type: u8,
    config: &Config,
) -> Result<(std::net::IpAddr, u16), ProxyError> {
    let timeout = config.client_read_timeout_secs;
    match addr_type {
        0x01 => {
            let mut b = [0u8; 6];
            read_exact_timeout(stream, &mut b, timeout).await?;
            Ok((
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])),
                u16::from_be_bytes([b[4], b[5]]),
            ))
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_exact_timeout(stream, &mut len, timeout).await?;
            let mut domain = vec![0u8; len[0] as usize];
            read_exact_timeout(stream, &mut domain, timeout).await?;
            let mut port = [0u8; 2];
            read_exact_timeout(stream, &mut port, timeout).await?;
            let domain_str = String::from_utf8_lossy(&domain);
            let ip = if let Ok(ip) = domain_str.parse::<std::net::IpAddr>() {
                ip
            } else {
                format!("{}:0", domain_str)
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut it| it.next().map(|a| a.ip()))
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            };
            let ip = if ip.is_unspecified() {
                config
                    .upstream_host
                    .parse::<std::net::IpAddr>()
                    .unwrap_or_else(|_| {
                        format!("{}:0", config.upstream_host)
                            .to_socket_addrs()
                            .ok()
                            .and_then(|mut it| it.next().map(|a| a.ip()))
                            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
                    })
            } else {
                ip
            };
            Ok((ip, u16::from_be_bytes(port)))
        }
        0x04 => {
            let mut b = [0u8; 18];
            read_exact_timeout(stream, &mut b, timeout).await?;
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&b[..16]);
            Ok((
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(oct)),
                u16::from_be_bytes([b[16], b[17]]),
            ))
        }
        _ => Err(ProxyError::UnsupportedBindType(addr_type)),
    }
}
