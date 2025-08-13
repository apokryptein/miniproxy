use crate::socks5::protocol::AddressType;
use anyhow::{Result, anyhow};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::{io::AsyncReadExt, net::TcpStream};

/// parse_address_from_stream contains logic to parse the network address
/// from an incoming client connection request: IPv4, IPv6, or domain name
/// and returns the resultant address as a String
pub async fn parse_address_from_stream(stream: &mut TcpStream) -> Result<(String, AddressType)> {
    // Read address type byte from stream
    let mut atype = [0u8; 1];
    stream.read_exact(&mut atype).await?;

    let addr_type =
        AddressType::from_byte(atype[0]).ok_or_else(|| anyhow!("[ERR] unknown address type"))?;

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
        _ => return Err(anyhow!("[ERR] unsupported or unknown address type")),
    };

    Ok((dest_addr, addr_type))
}

/// parse_address_from_packet contains logic to parse the network address
/// from an incoming UDP datagram packet: IPv4, IPv6, or domain name
/// and returns the resultant SocketAddr and number of bytes consumed in the operation
pub async fn parse_address_from_packet(
    packet: &[u8],
    start_offset: usize,
    atyp: u8,
) -> Result<(SocketAddr, usize)> {
    // Set offset to maintain start
    let mut offset = start_offset;

    // Get address type and parse
    let addr_str = match atyp {
        0x01 => parse_ipv4_address(packet, &mut offset)?,
        0x03 => parse_domain_address(packet, &mut offset)?,
        0x04 => parse_ipv6_address(packet, &mut offset)?,
        _ => return Err(anyhow!("unknown address type: {atyp}")),
    };

    // Parse address string into SocketAddr
    let socket_addr = match atyp {
        0x01 | 0x04 => addr_str
            .parse()
            .map_err(|e| anyhow!("failed to parse IP address: {e}"))?,
        0x03 => tokio::net::lookup_host(&addr_str)
            .await
            .map_err(|e| anyhow!("failed to resolve host '{addr_str}': {e}"))?
            .next()
            .ok_or_else(|| anyhow!("no IP address found for '{addr_str}'"))?,
        _ => unreachable!(),
    };

    // Get number of bytes consumed by the address
    let bytes_consumed = offset - start_offset;

    Ok((socket_addr, bytes_consumed))
}

/// parse_ipv4_address parses an IPv4 address from a byte slice
pub fn parse_ipv4_address(data: &[u8], offset: &mut usize) -> Result<String> {
    // Ensure we have enough data for an IPv4 address + port (6 bytes) ->
    if *offset + 6 > data.len() {
        return Err(anyhow!("not enough data for IPv4 address and port"));
    }

    // Grab IP bytes
    let ip_bytes: [u8; 4] = data[*offset..*offset + 4]
        .try_into()
        .map_err(|_| anyhow!("invalid IPv4 bytes"))?;

    // Instantiate new Ipv4Addr
    let ip = Ipv4Addr::from(ip_bytes);

    // Push offset past address -> 4 bytes
    *offset += 4;

    // Grab port -> BigEndian (network order)
    let port = u16::from_be_bytes([data[*offset], data[*offset + 1]]);

    // Push offset past port -> 2 bytes
    *offset += 2;

    Ok(format!("{ip}:{port}"))
}

/// parse_ipv6_address parses an IPv6 address from a byte slice
pub fn parse_ipv6_address(data: &[u8], offset: &mut usize) -> Result<String> {
    // Ensure we have enough data for an IPv6 address + port (18 bytes) ->
    if *offset + 18 > data.len() {
        return Err(anyhow!("not enough data for IPv6 address and port"));
    }

    // Grab IP bytes
    let ip_bytes: [u8; 16] = data[*offset..*offset + 16]
        .try_into()
        .map_err(|_| anyhow!("invalid IPv6 bytes"))?;

    // Instantiate new Ipv6Addr
    let ip = Ipv6Addr::from(ip_bytes);

    // Push offset past address -> 16 bytes
    *offset += 16;

    // Grab port -> BigEndian (network order)
    let port = u16::from_be_bytes([data[*offset], data[*offset + 1]]);

    // Push offset past port -> 2 bytes
    *offset += 2;

    Ok(format!("{ip}:{port}"))
}

/// parse_domain_address parses a domain from a byte slice
pub fn parse_domain_address(data: &[u8], offset: &mut usize) -> Result<String> {
    // Ensure there are bytes to read
    if *offset + 1 > data.len() {
        return Err(anyhow!("not enough data to read domain length"));
    }

    // Get domain length -> first byte of domain contains number of octets
    let domain_len = data[*offset] as usize;

    // Domain length checks
    if domain_len == 0 {
        return Err(anyhow!("domain length cannot be 0"));
    }

    if domain_len > 253 {
        return Err(anyhow!(
            "domain name too long: {domain_len} (max 253 bytes)"
        ));
    }

    if *offset + domain_len + 2 > data.len() {
        return Err(anyhow!("not enough data for domain and port"));
    }

    // Push offset to start of domain
    *offset += 1;

    // Get domain
    let domain_str = String::from_utf8(data[*offset..*offset + domain_len].to_vec())
        .map_err(|e| anyhow!("invalid domain: {e}"))?;

    // Push offset -> domain_len bytes
    *offset += domain_len;

    let port = u16::from_be_bytes([data[*offset], data[*offset + 1]]);

    // Push offset -> 2 bytes
    *offset += 2;

    Ok(format!("{domain_str}:{port}"))
}
