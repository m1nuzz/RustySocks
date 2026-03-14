#![windows_subsystem = "windows"]

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use std::sync::Arc;
use std::env;
use std::time::Duration;
use std::net::SocketAddr;
use std::collections::HashMap;
use tokio::sync::Mutex;
use dotenv::dotenv;
use log::{error, info, debug, warn};
use env_logger;
use clap::Parser;
use thiserror::Error;

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
}

pub fn get_config() -> Result<Config, ProxyError> {
    if let Ok(exe_path) = env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let _ = env::set_current_dir(exe_dir);
        }
    }

    dotenv().ok();

    let config = Config {
        local_addr: env::var("LOCAL_ADDR").unwrap_or_else(|_| "127.0.0.1:9053".to_string()),
        upstream_host: env::var("UPSTREAM_HOST")
            .map_err(ProxyError::UpstreamHostEnv)?,
        upstream_port: env::var("UPSTREAM_PORT")
            .map_err(ProxyError::UpstreamPortEnv)?
            .parse::<u16>()
            .map_err(ProxyError::UpstreamPortParse)?,
        upstream_user: env::var("UPSTREAM_USER")
            .map_err(ProxyError::UpstreamUserEnv)?,
        upstream_pass: env::var("UPSTREAM_PASS")
            .map_err(ProxyError::UpstreamPassEnv)?,
        connect_timeout_secs: env::var("CONNECT_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10),
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
    loop {
        let (client_socket, client_addr) = listener.accept().await?;
        info!("New client connection from {}", client_addr);
        let config_ref = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = handle_client(client_socket, config_ref).await {
                error!("Error handling client from {}: {}", client_addr, e);
            }
        });
    }
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

    let dest_addr_str: String;

    match addr_type {
        0x01 => {
            // IPv4 address
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            dest_info.extend_from_slice(&ip);
            dest_addr_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
        }
        0x03 => {
            // Domain name
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            dest_info.push(len_byte[0]);
            let mut domain = vec![0u8; len_byte[0] as usize];
            stream.read_exact(&mut domain).await?;
            dest_info.extend_from_slice(&domain);
            dest_addr_str = String::from_utf8_lossy(&domain).into_owned();
        }
        0x04 => {
            // IPv6 address
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            dest_info.extend_from_slice(&ip);
            dest_addr_str = format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
                ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]
            );
        }
        _ => {
            error!("Unsupported address type for client {}: {:#x}", client_addr, addr_type);
            return Err(ProxyError::UnsupportedAddressType(addr_type));
        }
    }

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
                ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
                ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]
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
    let n = client.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 {
        error!("SOCKS handshake failed for client {}: invalid format or version", client_addr);
        return Err(ProxyError::InvalidHandshake);
    }

    // Reply with no authentication required
    client.write_all(b"\x05\x00").await?;

    // Read request header (VER, CMD, RSV, ATYP)
    let (dest_info, dest_addr_str, dest_port) = parse_socks5_address(&mut client, client_addr).await?;

    info!("Client {} requested connection to {}:{}", client_addr, dest_addr_str, dest_port);

    let cmd = dest_info[1];

    match cmd {
        0x01 => {
            // CONNECT command - TCP relay
            handle_tcp_connect(client, config, dest_info, dest_addr_str, dest_port, client_addr).await
        }
        0x03 => {
            // UDP ASSOCIATE command
            handle_udp_associate(client, config, dest_addr_str, dest_port, client_addr).await
        }
        0x02 => {
            // BIND command - not supported
            error!("BIND command not supported for client {}", client_addr);
            let reply = b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00";
            let _ = client.write_all(reply).await;
            Err(ProxyError::UnsupportedCommand(0x02))
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
        TcpStream::connect(upstream_addr.clone())
    )
    .await
    .map_err(|_| ProxyError::UpstreamConnectionFailed(upstream_addr.clone(), std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out")))?
    .map_err(|e| ProxyError::UpstreamConnectionFailed(upstream_addr.clone(), e))?;
    
    debug!("Connected to upstream {}", upstream.peer_addr()?);

    let mut upstream = upstream;

    // Send authentication methods to upstream
    upstream.write_all(b"\x05\x02\x00\x02").await?;

    // Read upstream authentication response
    let mut auth_response = [0u8; 2];
    upstream.read_exact(&mut auth_response).await?;

    if auth_response[1] == 0x02 {
        // Upstream requires username/password authentication
        debug!("Upstream {} requires authentication.", upstream.peer_addr()?);
        
        // Build authentication packet: VER | ULEN | USERNAME | PLEN | PASSWD
        let mut auth_packet = Vec::new();
        auth_packet.push(0x01);
        auth_packet.push(config.upstream_user.len() as u8);
        auth_packet.extend_from_slice(config.upstream_user.as_bytes());
        auth_packet.push(config.upstream_pass.len() as u8);
        auth_packet.extend_from_slice(config.upstream_pass.as_bytes());

        upstream.write_all(&auth_packet).await?;

        // Read authentication status
        let mut status = [0u8; 2];
        upstream.read_exact(&mut status).await?;
        if status[1] != 0x00 {
            error!("Upstream authentication failed for client {}.", client_addr);
            return Err(ProxyError::UpstreamAuthFailed);
        }
        debug!("Upstream authentication successful for client {}.", client_addr);
    }

    // Send connection request to upstream
    upstream.write_all(&dest_info).await?;

    // Read upstream response header
    let mut upstream_resp_head = [0u8; 4];
    upstream.read_exact(&mut upstream_resp_head).await?;

    if upstream_resp_head[1] == 0x00 {
        // Success - read the bound address
        let bind_type = upstream_resp_head[3];
        match bind_type {
            0x01 => {
                let mut b = [0u8; 6];
                upstream.read_exact(&mut b).await?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                upstream.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize + 2];
                upstream.read_exact(&mut domain).await?;
            }
            0x04 => {
                let mut b = [0u8; 18];
                upstream.read_exact(&mut b).await?;
            }
            _ => {
                error!("Unsupported bind address type from upstream {}: {:#x}", upstream.peer_addr()?, bind_type);
                return Err(ProxyError::UnsupportedBindType(bind_type));
            }
        }

        // Send success response to client
        client.write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00").await?;
        info!("TCP connection established for client {}, proxying to {}:{}", client_addr, dest_addr_str, dest_port);

        // Start bidirectional data forwarding
        let (mut ci, mut co) = client.into_split();
        let (mut ui, mut uo) = upstream.into_split();

        let _ = tokio::try_join!(
            tokio::io::copy(&mut ci, &mut uo),
            tokio::io::copy(&mut ui, &mut co)
        ).map_err(|e| {
            debug!("Data proxying failed for client {}: {}", client_addr, e);
            e
        })?;
        info!("TCP proxying completed for client {}.", client_addr);

    } else {
        error!("Upstream connection failed for client {} with status: {:#x}", client_addr, upstream_resp_head[1]);
        return Err(ProxyError::UpstreamConnectionFailedStatus(upstream_resp_head[1]));
    }

    Ok(())
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

    // Bind a UDP socket on the same address as the TCP listener
    let local_addr = client.local_addr()?;
    let udp_socket = UdpSocket::bind(local_addr).await?;
    let udp_bound_addr = udp_socket.local_addr()?;
    
    debug!("UDP socket bound to {}", udp_bound_addr);

    // Send UDP association reply to client
    // For IPv4, we need to send the address in SOCKS5 format
    let ip = udp_bound_addr.ip();
    let port = udp_bound_addr.port();
    
    let reply = if ip.is_ipv4() {
        let ip_bytes = match ip {
            std::net::IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            _ => vec![0, 0, 0, 0],
        };
        build_socks5_reply(0x01, &ip_bytes, port)
    } else {
        let ip_bytes = match ip {
            std::net::IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
            _ => vec![0; 16],
        };
        build_socks5_reply(0x04, &ip_bytes, port)
    };

    client.write_all(&reply).await?;
    info!("UDP association established for client {}, UDP port: {}", client_addr, port);

    // Keep the TCP connection open and handle UDP relay
    // The TCP connection is used only to keep the association alive
    // Actual data transfer happens via UDP
    
    // Create a buffer for UDP packets
    let mut udp_buf = vec![0u8; 65535];
    let mut tcp_buf = vec![0u8; 1];
    
    // Track the last client UDP address for relaying
    use std::collections::HashMap;
    use tokio::sync::Mutex;
    
    let client_udp_addrs: Arc<Mutex<HashMap<String, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    let client_udp_addrs_clone = Arc::clone(&client_udp_addrs);
    
    // Spawn UDP relay task
    let udp_relay_handle = tokio::spawn(async move {
        let config_clone = Arc::clone(&config);
        run_udp_relay(udp_socket, udp_buf, config_clone, client_udp_addrs_clone, client_addr).await
    });

    // Wait for TCP connection to close (client disconnects)
    loop {
        let n = client.read(&mut tcp_buf).await?;
        if n == 0 {
            // TCP connection closed
            debug!("TCP control connection closed for client {}", client_addr);
            break;
        }
    }

    // Abort UDP relay when TCP connection closes
    udp_relay_handle.abort();
    info!("UDP association terminated for client {}", client_addr);

    Ok(())
}

/// Run UDP relay between client and upstream
async fn run_udp_relay(
    udp_socket: UdpSocket,
    _buf: Vec<u8>,
    config: Arc<Config>,
    client_udp_addrs: Arc<Mutex<HashMap<String, SocketAddr>>>,
    _server_client_addr: SocketAddr,
) -> Result<(), ProxyError> {
    use tokio::net::UdpSocket as TokioUdpSocket;
    
    // We'll use a single upstream UDP socket for all communications
    let upstream_udp = TokioUdpSocket::bind("0.0.0.0:0").await?;
    
    // Set timeout for UDP operations
    let timeout = Duration::from_secs(config.connect_timeout_secs);
    
    // Separate buffers for client and upstream
    let mut client_buf = vec![0u8; 65535];
    let mut upstream_buf = vec![0u8; 65535];
    
    loop {
        tokio::select! {
            // Receive from client
            result = udp_socket.recv_from(&mut client_buf) => {
                let (n, client_udp_addr) = result?;
                
                // Parse SOCKS5 UDP header
                let (header_len, dest_addr, dest_port) = parse_udp_header(&client_buf[..n])?;
                let payload = &client_buf[header_len..n];
                
                debug!("UDP from client {} to {}:{} ({} bytes)", client_udp_addr, dest_addr, dest_port, payload.len());
                
                // Store client UDP address for response routing
                {
                    let mut addrs = client_udp_addrs.lock().await;
                    addrs.insert(format!("{}:{}", dest_addr, dest_port), client_udp_addr);
                }
                
                // Resolve destination and forward to upstream
                let upstream_target = format!("{}:{}", config.upstream_host, config.upstream_port);
                
                // Build packet for upstream (with SOCKS5 header)
                let mut upstream_packet = Vec::new();
                upstream_packet.push(0x00); // RSV
                upstream_packet.push(0x00); // RSV
                upstream_packet.push(0x00); // FRAG
                
                // Add destination address
                if let Ok(ip) = dest_addr.parse::<std::net::IpAddr>() {
                    if ip.is_ipv4() {
                        upstream_packet.push(0x01);
                        if let std::net::IpAddr::V4(ipv4) = ip {
                            upstream_packet.extend_from_slice(&ipv4.octets());
                        }
                    } else {
                        upstream_packet.push(0x04);
                        if let std::net::IpAddr::V6(ipv6) = ip {
                            upstream_packet.extend_from_slice(&ipv6.octets());
                        }
                    }
                } else {
                    // Domain name
                    upstream_packet.push(0x03);
                    upstream_packet.push(dest_addr.len() as u8);
                    upstream_packet.extend_from_slice(dest_addr.as_bytes());
                }
                upstream_packet.extend_from_slice(&dest_port.to_be_bytes());
                upstream_packet.extend_from_slice(payload);
                
                // Send to upstream
                let _ = upstream_udp.send_to(&upstream_packet, &upstream_target).await;
            }
            
            // Receive from upstream
            result = upstream_udp.recv_from(&mut upstream_buf) => {
                let (n, _upstream_addr) = result?;
                
                // Parse response from upstream
                let (header_len, _src_addr, src_port) = parse_udp_header(&upstream_buf[..n])?;
                let payload = &upstream_buf[header_len..n];
                
                // Find the original client UDP address
                let client_udp_addr = {
                    let addrs = client_udp_addrs.lock().await;
                    // Try to find by port first
                    addrs.values().next().copied()
                };
                
                if let Some(client_addr) = client_udp_addr {
                    // Build response packet with SOCKS5 header
                    let mut response = build_udp_header(0x01, &[0, 0, 0, 0], src_port);
                    response.extend_from_slice(payload);
                    
                    let _ = udp_socket.send_to(&response, client_addr).await;
                    debug!("UDP to client {} from port {} ({} bytes)", client_addr, src_port, payload.len());
                }
            }
            
            // Timeout for idle connection
            _ = tokio::time::sleep(timeout * 10) => {
                debug!("UDP relay timeout");
                break;
            }
        }
    }
    
    Ok(())
}
