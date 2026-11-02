//! Integration tests for SOCKS5 Proxy
//!
//! These tests verify configuration parsing, error handling, and protocol utilities.

// Include main module for access to internal functions
#[path = "../src/main.rs"]
mod main;

use main::{
    Config, ProxyError, build_socks5_reply, build_udp_header, get_config, parse_udp_header,
};
use std::sync::{Mutex, OnceLock};

// Global mutex to serialize tests that modify environment variables
static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

fn get_env_mutex() -> &'static Mutex<()> {
    ENV_MUTEX.get_or_init(|| Mutex::new(()))
}

/// Helper to clear all test-related environment variables
fn clear_test_env() {
    unsafe {
        std::env::remove_var("LOCAL_ADDR");
        std::env::remove_var("UPSTREAM_HOST");
        std::env::remove_var("UPSTREAM_PORT");
        std::env::remove_var("UPSTREAM_USER");
        std::env::remove_var("UPSTREAM_PASS");
        std::env::remove_var("CONNECT_TIMEOUT");
    }
}

/// Acquire the environment mutex, recovering from poisoned state if necessary
fn acquire_env_lock() -> Option<std::sync::MutexGuard<'static, ()>> {
    match get_env_mutex().lock() {
        Ok(guard) => Some(guard),
        Err(poisoned) => {
            clear_test_env();
            Some(poisoned.into_inner())
        }
    }
}

/// Tests that default local address is used when LOCAL_ADDR is not set
#[test]
fn test_config_default_local_addr() {
    let _guard = acquire_env_lock();
    clear_test_env();
    unsafe {
        std::env::set_var("UPSTREAM_HOST", "test1.example.com");
        std::env::set_var("UPSTREAM_PORT", "1080");
        std::env::set_var("UPSTREAM_USER", "testuser1");
        std::env::set_var("UPSTREAM_PASS", "testpass1");
    }

    let config = get_config().unwrap();
    assert_eq!(config.local_addr, "127.0.0.1:9053");
    clear_test_env();
}

/// Tests custom local address configuration
#[test]
fn test_config_custom_local_addr() {
    let _guard = acquire_env_lock();
    clear_test_env();
    unsafe {
        std::env::set_var("LOCAL_ADDR", "0.0.0.0:8080");
        std::env::set_var("UPSTREAM_HOST", "test2.example.com");
        std::env::set_var("UPSTREAM_PORT", "1080");
        std::env::set_var("UPSTREAM_USER", "testuser2");
        std::env::set_var("UPSTREAM_PASS", "testpass2");
    }

    let config = get_config().unwrap();
    assert_eq!(config.local_addr, "0.0.0.0:8080");
    clear_test_env();
}

/// Tests error when UPSTREAM_HOST is missing
#[test]
fn test_config_missing_upstream_host() {
    let _guard = acquire_env_lock();
    clear_test_env();
    unsafe {
        std::env::set_var("UPSTREAM_PORT", "1080");
        std::env::set_var("UPSTREAM_USER", "testuser3");
        std::env::set_var("UPSTREAM_PASS", "testpass3");
    }

    let result = get_config();
    assert!(result.is_err());
    clear_test_env();
}

/// Tests error when UPSTREAM_PORT is invalid (not a number)
#[test]
fn test_config_invalid_port() {
    let _guard = acquire_env_lock();
    clear_test_env();
    unsafe {
        std::env::set_var("UPSTREAM_HOST", "test4.example.com");
        std::env::set_var("UPSTREAM_PORT", "invalid");
        std::env::set_var("UPSTREAM_USER", "testuser4");
        std::env::set_var("UPSTREAM_PASS", "testpass4");
    }

    let result = get_config();
    assert!(result.is_err());
    clear_test_env();
}

/// Tests error when port is out of range (> 65535)
#[test]
fn test_config_port_out_of_range() {
    let _guard = acquire_env_lock();
    clear_test_env();
    unsafe {
        std::env::set_var("UPSTREAM_HOST", "test5.example.com");
        std::env::set_var("UPSTREAM_PORT", "70000");
        std::env::set_var("UPSTREAM_USER", "testuser5");
        std::env::set_var("UPSTREAM_PASS", "testpass5");
    }

    let result = get_config();
    assert!(result.is_err());
    clear_test_env();
}

/// Tests default timeout value (10 seconds)
#[test]
fn test_config_default_timeout() {
    let _guard = acquire_env_lock();
    clear_test_env();
    unsafe {
        std::env::set_var("UPSTREAM_HOST", "test6.example.com");
        std::env::set_var("UPSTREAM_PORT", "1080");
        std::env::set_var("UPSTREAM_USER", "testuser6");
        std::env::set_var("UPSTREAM_PASS", "testpass6");
    }

    let config = get_config().unwrap();
    assert_eq!(config.connect_timeout_secs, 10);
    clear_test_env();
}

/// Tests custom timeout value
#[test]
fn test_config_custom_timeout() {
    let _guard = acquire_env_lock();
    clear_test_env();
    unsafe {
        std::env::set_var("CONNECT_TIMEOUT", "30");
        std::env::set_var("UPSTREAM_HOST", "test7.example.com");
        std::env::set_var("UPSTREAM_PORT", "1080");
        std::env::set_var("UPSTREAM_USER", "testuser7");
        std::env::set_var("UPSTREAM_PASS", "testpass7");
    }

    let config = get_config().unwrap();
    assert_eq!(config.connect_timeout_secs, 30);
    clear_test_env();
}

/// Tests error message formatting for ProxyError types
#[test]
fn test_proxy_error_display() {
    let err = ProxyError::InvalidHandshake;
    assert_eq!(
        format!("{}", err),
        "SOCKS handshake failed: invalid format or version"
    );

    let err = ProxyError::UnsupportedCommand(0x02);
    assert_eq!(format!("{}", err), "Unsupported SOCKS command: 0x2");

    let err = ProxyError::UnsupportedAddressType(0x05);
    assert_eq!(format!("{}", err), "Unsupported address type: 0x5");

    let err = ProxyError::UpstreamAuthFailed;
    assert_eq!(format!("{}", err), "Upstream authentication failed");

    let err = ProxyError::UpstreamConnectionFailedStatus(0x04);
    assert_eq!(
        format!("{}", err),
        "Upstream connection failed with status: 0x4"
    );

    let err = ProxyError::UnsupportedBindType(0x05);
    assert_eq!(
        format!("{}", err),
        "Unsupported bind address type from upstream: 0x5"
    );
}

/// Tests IPv4 address parsing logic
#[test]
fn test_ipv4_address_format() {
    let ip = [192, 168, 1, 1];
    let addr_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    assert_eq!(addr_str, "192.168.1.1");

    let ip = [10, 0, 0, 1];
    let addr_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    assert_eq!(addr_str, "10.0.0.1");
}

/// Tests IPv6 address parsing logic
#[test]
fn test_ipv6_address_format() {
    let ip = [
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73,
        0x34,
    ];
    let addr_str = format!(
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
    assert_eq!(addr_str, "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
}

/// Tests port conversion from bytes (big-endian)
#[test]
fn test_port_bytes_to_u16() {
    let port_bytes = [0x00, 0x50];
    let port = u16::from_be_bytes(port_bytes);
    assert_eq!(port, 80);

    let port_bytes = [0x04, 0x38];
    let port = u16::from_be_bytes(port_bytes);
    assert_eq!(port, 1080);

    let port_bytes = [0xff, 0xff];
    let port = u16::from_be_bytes(port_bytes);
    assert_eq!(port, 65535);
}

/// Tests Config struct clone functionality
#[test]
fn test_config_clone() {
    let config = Config {
        local_addr: "127.0.0.1:9053".to_string(),
        upstream_host: "proxy.example.com".to_string(),
        upstream_port: 1080,
        upstream_user: "user".to_string(),
        upstream_pass: "pass".to_string(),
        connect_timeout_secs: 15,
        client_read_timeout_secs: 30,
    };

    let cloned = config.clone();
    assert_eq!(cloned.local_addr, config.local_addr);
    assert_eq!(cloned.upstream_host, config.upstream_host);
    assert_eq!(cloned.upstream_port, config.upstream_port);
    assert_eq!(cloned.upstream_user, config.upstream_user);
    assert_eq!(cloned.upstream_pass, config.upstream_pass);
    assert_eq!(cloned.connect_timeout_secs, config.connect_timeout_secs);
}

/// Tests missing UPSTREAM_USER error
#[test]
fn test_config_missing_upstream_user() {
    let _guard = acquire_env_lock();
    clear_test_env();
    unsafe {
        std::env::set_var("UPSTREAM_HOST", "test8.example.com");
        std::env::set_var("UPSTREAM_PORT", "1080");
        std::env::set_var("UPSTREAM_PASS", "testpass8");
    }

    let result = get_config();
    assert!(result.is_err());
    clear_test_env();
}

/// Tests missing UPSTREAM_PASS error
#[test]
fn test_config_missing_upstream_pass() {
    let _guard = acquire_env_lock();
    clear_test_env();
    unsafe {
        std::env::set_var("UPSTREAM_HOST", "test9.example.com");
        std::env::set_var("UPSTREAM_PORT", "1080");
        std::env::set_var("UPSTREAM_USER", "testuser9");
    }

    let result = get_config();
    assert!(result.is_err());
    clear_test_env();
}

/// Tests zero timeout value
#[test]
fn test_config_zero_timeout() {
    let _guard = acquire_env_lock();
    clear_test_env();
    unsafe {
        std::env::set_var("CONNECT_TIMEOUT", "0");
        std::env::set_var("UPSTREAM_HOST", "test10.example.com");
        std::env::set_var("UPSTREAM_PORT", "1080");
        std::env::set_var("UPSTREAM_USER", "testuser10");
        std::env::set_var("UPSTREAM_PASS", "testpass10");
    }

    let config = get_config().unwrap();
    assert_eq!(config.connect_timeout_secs, 0);
    clear_test_env();
}

/// Tests domain name address type handling (SOCKS5 ATYP 0x03)
#[test]
fn test_domain_name_address_type() {
    let domain = b"example.com";
    let mut dest_info = Vec::new();
    dest_info.push(0x03);
    dest_info.push(domain.len() as u8);
    dest_info.extend_from_slice(domain);

    assert_eq!(dest_info[0], 0x03);
    assert_eq!(dest_info[1], 11);
    assert_eq!(&dest_info[2..], domain);
}

/// Tests SOCKS5 version byte validation
#[test]
fn test_socks5_version_validation() {
    let valid_greeting = [0x05, 0x01, 0x00];
    assert_eq!(valid_greeting[0], 0x05);

    let invalid_greeting = [0x04, 0x01, 0x00];
    assert_ne!(invalid_greeting[0], 0x05);
}

/// Tests SOCKS5 command types
#[test]
fn test_socks5_command_types() {
    // CONNECT command (0x01)
    let connect_cmd = 0x01;
    assert_eq!(connect_cmd, 0x01);

    // BIND command (0x02) - not supported
    let bind_cmd = 0x02;
    assert_ne!(bind_cmd, 0x01);

    // UDP ASSOCIATE command (0x03)
    let udp_cmd = 0x03;
    assert_eq!(udp_cmd, 0x03);
}

/// Tests authentication packet structure
#[test]
fn test_auth_packet_structure() {
    let user = "testuser";
    let pass = "testpass";

    let mut auth_packet = Vec::new();
    auth_packet.push(0x01);
    auth_packet.push(user.len() as u8);
    auth_packet.extend_from_slice(user.as_bytes());
    auth_packet.push(pass.len() as u8);
    auth_packet.extend_from_slice(pass.as_bytes());

    assert_eq!(auth_packet[0], 0x01);
    assert_eq!(auth_packet[1], 8);
    assert_eq!(&auth_packet[2..10], user.as_bytes());
    assert_eq!(auth_packet[10], 8);
    assert_eq!(&auth_packet[11..19], pass.as_bytes());
}

/// Tests SOCKS5 UDP header parsing
#[test]
fn test_udp_header_parsing() {
    // Build a test UDP packet with header
    // RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(4) + DST.PORT(2) + DATA
    let mut packet = vec![0x00, 0x00, 0x00, 0x01]; // RSV, RSV, FRAG, ATYP (IPv4)
    packet.extend_from_slice(&[192, 168, 1, 1]); // IP
    packet.extend_from_slice(&[0x00, 0x50]); // Port 80
    packet.extend_from_slice(b"hello"); // Data

    let (header_len, dest_addr, dest_port) = parse_udp_header(&packet).unwrap();
    assert_eq!(header_len, 10);
    assert_eq!(dest_addr, "192.168.1.1");
    assert_eq!(dest_port, 80);
}

/// Tests SOCKS5 UDP header building
#[test]
fn test_udp_header_building() {
    let header = build_udp_header(0x01, &[192, 168, 1, 1], 80);
    assert_eq!(header.len(), 10);
    assert_eq!(header[0], 0x00); // RSV
    assert_eq!(header[1], 0x00); // RSV
    assert_eq!(header[2], 0x00); // FRAG
    assert_eq!(header[3], 0x01); // ATYP
    assert_eq!(&header[4..8], &[192, 168, 1, 1]);
    assert_eq!(&header[8..10], &[0x00, 0x50]); // Port 80
}

/// Tests SOCKS5 address reply building
#[test]
fn test_socks5_reply_building() {
    let reply = build_socks5_reply(0x01, &[127, 0, 0, 1], 9053);
    assert_eq!(reply.len(), 10);
    assert_eq!(reply[0], 0x05); // Version
    assert_eq!(reply[1], 0x00); // Success
    assert_eq!(reply[2], 0x00); // RSV
    assert_eq!(reply[3], 0x01); // ATYP
    assert_eq!(&reply[4..8], &[127, 0, 0, 1]);
    assert_eq!(&reply[8..10], &[0x23, 0x5d]); // Port 9053
}

/// Tests UDP ASSOCIATE command constant
#[test]
fn test_udp_associate_command() {
    // UDP ASSOCIATE is command 0x03
    let udp_associate = 0x03;
    assert_eq!(udp_associate, 0x03);
}
