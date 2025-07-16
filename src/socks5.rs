use anyhow::{Result, anyhow, bail};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// These structs help to document the SOCKS5 protocol structure
// but aren't used in this implementation for simplicity
// ClientHello represents a SOCKS5 client hello
// struct ClientHello {
//     /// SOCKS version -> 0x05
//     version: u8,
//
//     /// Vector of SOCKS5 authentication methods supported by client
//     auth_methods: Vec<u8>,
// }
//
// /// ServerChoice represents the server's auth method selection
// struct ServerChoice {
//     /// SOCKS version -> 0x05
//     version: u8,
//
//     /// Authentication method selected by server
//     method: u8,
// }
//
// ConnectRequest represents a client connection request
// struct ConnectRequest {
//     /// SOCKS version -> 0x05
//     version: u8,
//
//     /// SOCKS5 command (connect, bind)
//     command: u8, // 0x01=connect
//
//     /// Must be set to 0x00 as per specification
//     reserved: u8,
//
//     /// Address type (IPv4, domain, IPv6)
//     addr_type: u8, // 0x01=IPv4, 0x03=domain
//
//     /// Destination address
//     addr: Address,
//
//     /// Destination port
//     port: u16,
// }

/// Address represents a network address or domain to be used as the
/// SOCKS5 target address
#[derive(Debug, Clone)]
enum Address {
    IPv4([u8; 4]),
    DomainName(String),
    IPv6([u8; 16]),
}

/// AddressType represents the SOCKS5 address types:
/// IPv4, Domain Name, IPv6
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum AddressType {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04,
}

/// TargetAddress represents a forward proxy address and port
struct TargetAddress {
    address: Address,
    port: String,
}

/// Version represents available SOCKS proxy versions
/// I included this for readability and clarity, but this
/// implementation only supports SOCKS5
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum Version {
    SOCKS5 = 0x05,
}

/// AuthMethod represents available SOCKS5
/// authentication methods
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum AuthMethod {
    NoAuth = 0x00,
    Gssapi = 0x01,
    UserPass = 0x02,
    // 0x03 - 0x7f: IANA reserved
    // 0x80 - 0xFE: private methods
    NoAcceptable = 0xFF,
}

/// Command represents SOCKS5 protocol commands
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum ReplyCode {
    Succeeded = 0x00,
    ServerFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddrTypeUnsupported = 0x08,
    // 0x09 - 0xFF: unassigned
}

// RSV: Fields marked RESERVED (RSV) must be set to X'00'.
const RSV: u8 = 0x00;

async fn handle_socks5(stream: &mut TcpStream) -> Result<()> {
    // Negotiate authentication with client
    negotiate_auth(stream).await?;

    // Handle connection requet from client
    handle_connect_request(stream).await?;

    Ok(())
}

async fn negotiate_auth(stream: &mut TcpStream) -> Result<()> {
    // ClientHello format
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+

    // Instantiate handshake buffer & read
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    // Parse version and client methods from handshake
    let version = buf[0];
    let n_methods = buf[1];

    // Ensure version is 0x05 -> SOCKS5
    if version != Version::SOCKS5 as u8 {
        bail!("[ERR] not SOCKS5");
    }

    // TODO: implement username/pass auth

    // Read auth methods: currently only implementing no-auth
    let mut methods = vec![0u8; n_methods as usize];
    stream.read_exact(&mut methods).await?;

    // ServerChoice method selection reply format
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+

    // Write response to client
    // TODO: clean up enum conversion later
    stream
        .write_all(&[Version::SOCKS5 as u8, AuthMethod::NoAuth as u8])
        .await?;

    Ok(())
}

async fn handle_connect_request(stream: &mut TcpStream) -> Result<()> {
    // SOCKS5 request format
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

    // Instantiate a request buffer & read
    let mut reqbuf = [0u8; 3];
    stream.read_exact(&mut reqbuf).await?;

    // Parse
    let version = reqbuf[0];
    let command = reqbuf[1];
    // Not retrieving RSV (RESERVED) -> 0x00

    // Ensure version is 0x05 -> SOCKS5
    if version != Version::SOCKS5 as u8 {
        bail!("[ERR] not SOCKS5");
    }

    // Ensure we are getting a CONNECT request
    let target = match command {
        0x01 => parse_target_address(stream).await?,
        0x02 => {
            send_reply(stream, ReplyCode::CommandNotSupported, "0.0.0.0:0".parse()?).await?;
            return Err(anyhow!("[ERR] BIND not supported"));
        }
        0x03 => {
            send_reply(stream, ReplyCode::CommandNotSupported, "0.0.0.0:0".parse()?).await?;
            return Err(anyhow!("[ERR] UDP ASSOCIATE not supported"));
        }
        _ => {
            send_reply(stream, ReplyCode::ServerFailure, "0.0.0.0:0".parse()?).await?;
            return Err(anyhow!("[ERR] unknown command"));
        }
    };

    match TcpStream::connect(&target).await {
        Ok(mut outbound) => {
            // Send OK reply
            send_reply(stream, ReplyCode::Succeeded, outbound.local_addr()?).await?;

            // TODO: start proxying here
            Ok(())
        }
        Err(e) => {
            let reply_code = match e.kind() {
                io::ErrorKind::ConnectionRefused => ReplyCode::ConnectionRefused,
                io::ErrorKind::HostUnreachable => ReplyCode::HostUnreachable,
                _ => ReplyCode::ServerFailure,
            };
            send_reply(stream, reply_code, "0.0.0.0:0".parse()?).await?;
            Err(e.into())
        }
    }
}

async fn parse_target_address(stream: &mut TcpStream) -> Result<String> {
    let mut atype = [0u8; 1];
    stream.read_exact(&mut atype).await?;

    // Match type and extract address or domain name
    let dest_addr = match atype[0] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let ip = Ipv4Addr::from(addr);

            //Read port
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let dest_port = u16::from_be_bytes(port_buf);

            format!("{}:{}", ip, dest_port)
        }
        0x03 => {
            // First octet in DomainName contains the number of
            // octets to follow
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;

            // Read domain and convert to string
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let domain_str = String::from_utf8(domain)?;

            //Read port
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let dest_port = u16::from_be_bytes(port_buf);

            format!("{}:{}", domain_str, dest_port)
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let ip = Ipv6Addr::from(addr);

            //Read port
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let dest_port = u16::from_be_bytes(port_buf);

            format!("{}:{}", ip, dest_port)
        }
        _ => return Err(anyhow!("[ERR] unknown address type")),
    };

    Ok(dest_addr)
}

async fn send_reply(
    stream: &mut TcpStream,
    reply_code: ReplyCode,
    bound_addr: SocketAddr,
) -> Result<()> {
    // SOCKS5 reply format
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

    // Build initial reply vec
    let mut reply = vec![Version::SOCKS5 as u8, reply_code as u8, RSV];

    // Parse bound_addr as IPv4/6 and finish build accordingly
    match bound_addr {
        SocketAddr::V4(addr) => {
            reply.push(AddressType::IPv4 as u8);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            reply.push(AddressType::IPv6 as u8);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    // Write reply
    stream.write_all(&reply).await?;
    Ok(())
}
