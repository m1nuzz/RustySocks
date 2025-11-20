#![windows_subsystem = "windows"]

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use std::sync::Arc;
use std::env;
use dotenv::dotenv;
use log::{error, info};
use env_logger;

#[derive(Clone)]
struct Config {
    local_addr: String,
    upstream_host: String,
    upstream_port: u16,
    upstream_user: String,
    upstream_pass: String,
}

fn get_config() -> Result<Config, Box<dyn Error>> {
    if let Ok(exe_path) = env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let _ = env::set_current_dir(exe_dir);
        }
    }
    
    dotenv().ok();

    let config = Config {
        local_addr: env::var("LOCAL_ADDR").unwrap_or_else(|_| "127.0.0.1:9053".to_string()),
        upstream_host: env::var("UPSTREAM_HOST")
            .map_err(|e| format!("Failed to get UPSTREAM_HOST from .env: {}", e))?,
        upstream_port: env::var("UPSTREAM_PORT")
            .map_err(|e| format!("Failed to get UPSTREAM_PORT from .env: {}", e))?
            .parse::<u16>()
            .map_err(|e| format!("Failed to parse UPSTREAM_PORT: {}", e))?,
        upstream_user: env::var("UPSTREAM_USER")
            .map_err(|e| format!("Failed to get UPSTREAM_USER from .env: {}", e))?,
        upstream_pass: env::var("UPSTREAM_PASS")
            .map_err(|e| format!("Failed to get UPSTREAM_PASS from .env: {}", e))?,
    };

    Ok(config)
}

use clap::Parser;

/// SOCKS5 Proxy
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Enable logging
    #[arg(short, long)]
    log: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    if args.log {
        env_logger::init();
    }
    
    let config = get_config()?;
    let config = Arc::new(config);
    info!("SOCKS5 Proxy listening on {}", config.local_addr);
    let listener = TcpListener::bind(&config.local_addr).await?;
    loop {
        let (client_socket, _) = listener.accept().await?;
        info!("New client connection from {:?}", client_socket.peer_addr());
        let config_ref = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = handle_client(client_socket, config_ref).await {
                error!("Error handling client: {}", e);
            }
        });
    }
}

async fn handle_client(mut client: TcpStream, config: Arc<Config>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let client_addr = client.peer_addr()?;
    info!("Handling client from {:?}", client_addr);

    let mut buf = [0u8; 262];
    let n = client.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 { 
        error!("SOCKS handshake failed for client {:?}: invalid format or version", client_addr);
        return Err(format!("SOCKS handshake failed: invalid format or version for client {:?}", client_addr).into()); 
    }
    
    client.write_all(b"\x05\x00").await?;

    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;

    if head[1] != 0x01 { 
        error!("Unsupported SOCKS command for client {:?}: {:?}", client_addr, head[1]);
        return Err(format!("Unsupported SOCKS command: {:?}", head[1]).into()); 
    } 

    let addr_type = head[3];
    let mut dest_info = Vec::new();
    dest_info.extend_from_slice(&head); 

    let dest_addr_str: String;

    match addr_type {
        0x01 => { 
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).await?;
            dest_info.extend_from_slice(&ip);
            dest_addr_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
        }
        0x03 => { 
            let mut len_byte = [0u8; 1];
            client.read_exact(&mut len_byte).await?;
            dest_info.push(len_byte[0]);
            let mut domain = vec![0u8; len_byte[0] as usize];
            client.read_exact(&mut domain).await?;
            dest_info.extend_from_slice(&domain);
            dest_addr_str = String::from_utf8_lossy(&domain).into_owned();
        }
        _ => {
            error!("Unsupported address type for client {:?}: {:?}", client_addr, addr_type);
            return Err(format!("Unsupported address type: {:?}", addr_type).into()); 
        },
    }

    let mut port_bytes = [0u8; 2];
    client.read_exact(&mut port_bytes).await?;
    dest_info.extend_from_slice(&port_bytes);
    let dest_port = u16::from_be_bytes(port_bytes);

    info!("Client {:?} requested connection to {}:{}", client_addr, dest_addr_str, dest_port);

    let upstream_addr = format!("{}:{}", config.upstream_host, config.upstream_port);
    let mut upstream = TcpStream::connect(upstream_addr.clone()).await.map_err(|e| {
        error!("Failed to connect to upstream {}: {}", upstream_addr, e);
        format!("Failed to connect to upstream {}: {}", upstream_addr, e)
    })?;
    info!("Connected to upstream {:?}", upstream.peer_addr());

    upstream.write_all(b"\x05\x02\x00\x02").await?;

    let mut auth_response = [0u8; 2];
    upstream.read_exact(&mut auth_response).await?;

    if auth_response[1] == 0x02 {
        info!("Upstream {:?} requires authentication.", upstream.peer_addr());
        let mut auth_packet = Vec::new();
        auth_packet.push(0x01);
        auth_packet.push(config.upstream_user.len() as u8);
        auth_packet.extend_from_slice(config.upstream_user.as_bytes());
        auth_packet.push(config.upstream_pass.len() as u8);
        auth_packet.extend_from_slice(config.upstream_pass.as_bytes());
        
        upstream.write_all(&auth_packet).await?;

        let mut status = [0u8; 2];
        upstream.read_exact(&mut status).await?;
        if status[1] != 0x00 {
            error!("Upstream authentication failed for client {:?}.", client_addr);
            return Err("Upstream authentication failed.".into());
        }
        info!("Upstream authentication successful for client {:?}.", client_addr);
    }

    upstream.write_all(&dest_info).await?;

    let mut upstream_resp_head = [0u8; 4];
    upstream.read_exact(&mut upstream_resp_head).await?;

    if upstream_resp_head[1] == 0x00 {
        let bind_type = upstream_resp_head[3];
        match bind_type {
            0x01 => { let mut b = [0u8; 6]; upstream.read_exact(&mut b).await?; },
            0x03 => { 
                let mut len = [0u8; 1];
                upstream.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize + 2];
                upstream.read_exact(&mut domain).await?;
            },
            _ => {
                error!("Unsupported bind address type from upstream {:?}: {:?}", upstream.peer_addr(), bind_type);
                return Err(format!("Unsupported bind address type from upstream: {:?}", bind_type).into());
            }
        }
        
        client.write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00").await?;
        info!("SOCKS5 connection established for client {:?}, proxying data to {}:{}.", client_addr, dest_addr_str, dest_port);

        let (mut ci, mut co) = client.into_split();
        let (mut ui, mut uo) = upstream.into_split();

        let _ = tokio::try_join!(
            tokio::io::copy(&mut ci, &mut uo),
            tokio::io::copy(&mut ui, &mut co)
        ).map_err(|e| {
            error!("Data proxying failed for client {:?}: {}", client_addr, e);
            e
        })?;
        info!("Data proxying completed for client {:?}.", client_addr);

    } else {
        error!("Upstream connection failed for client {:?} with status: {:?}", client_addr, upstream_resp_head[1]);
        return Err(format!("Upstream connection failed with status: {:?}", upstream_resp_head[1]).into());
    }

    Ok(())
}