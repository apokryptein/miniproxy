use crate::socks5::protocol::{AddressType, Command, RSV, ReplyCode, Version};
use anyhow::{Result, anyhow, bail};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

// ================
// CONNECT COMMAND
// ================

/// handle_connect_request handles incoming connection requests from a SOCKS client
/// parses the request, and returns an outbound stream to the target address
pub async fn handle_connect_request(stream: &mut TcpStream) -> Result<TcpStream> {
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
    let target = match Command::from_byte(command) {
        Some(Command::Connect) => parse_target_address(stream).await?,
        Some(Command::Bind) => {
            send_reply(stream, ReplyCode::CommandNotSupported, "0.0.0.0:0".parse()?).await?;
            return Err(anyhow!("[ERR] BIND not supported"));
        }
        Some(Command::UdpAssociate) => {
            send_reply(stream, ReplyCode::CommandNotSupported, "0.0.0.0:0".parse()?).await?;
            return Err(anyhow!("[ERR] UDP ASSOCIATE not supported"));
        }
        _ => {
            send_reply(stream, ReplyCode::ServerFailure, "0.0.0.0:0".parse()?).await?;
            return Err(anyhow!("[ERR] unknown command"));
        }
    };

    // Connect to target
    match TcpStream::connect(&target).await {
        Ok(outbound) => {
            // Send OK reply
            send_reply(stream, ReplyCode::Succeeded, outbound.local_addr()?).await?;

            // Return outbound stream
            Ok(outbound)
        }
        Err(e) => {
            let reply_code = match e.kind() {
                io::ErrorKind::ConnectionRefused => ReplyCode::ConnectionRefused,
                io::ErrorKind::HostUnreachable => ReplyCode::HostUnreachable,
                io::ErrorKind::NetworkUnreachable => ReplyCode::NetworkUnreachable,
                io::ErrorKind::PermissionDenied => ReplyCode::ConnectionNotAllowed,
                _ => ReplyCode::ServerFailure,
            };
            send_reply(stream, reply_code, "0.0.0.0:0".parse()?).await?;
            Err(e.into())
        }
    }
}

// ===============
// UDP ASSOCIATE
// ===============

// TODO: implement UDP ASSOCIATE command

// =========
// HELPERS
// =========

/// parse_target_address contains logic to parse the network address
/// from an incoming client connection request: IPv4, IPv6, or domain name
/// and returns the resultant address as a String
async fn parse_target_address(stream: &mut TcpStream) -> Result<String> {
    // Read address type byte from stream
    let mut atype = [0u8; 1];
    stream.read_exact(&mut atype).await?;

    // Match type and extract address or domain name
    let dest_addr = match AddressType::from_byte(atype[0]) {
        Some(AddressType::IPv4) => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let ip = Ipv4Addr::from(addr);

            //Read port
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let dest_port = u16::from_be_bytes(port_buf);

            format!("{ip}:{dest_port}")
        }
        Some(AddressType::DomainName) => {
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

            format!("{domain_str}:{dest_port}")
        }
        Some(AddressType::IPv6) => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let ip = Ipv6Addr::from(addr);

            //Read port
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let dest_port = u16::from_be_bytes(port_buf);

            format!("{ip}:{dest_port}")
        }
        _ => return Err(anyhow!("[ERR] unknown address type")),
    };

    Ok(dest_addr)
}

/// send_reply handles logic for sending replies from the SOCKS server to
/// the client
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
