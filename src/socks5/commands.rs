use crate::socks5::protocol::{AddressType, Command, MAX_DGRAM, RSV, ReplyCode, Version};
use anyhow::{Result, anyhow, bail};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpStream, UdpSocket},
    select,
};
use tracing::{error, info};

/// TransportProcol is an enum holding either a tokio
/// TcpStream or UdpSocket
pub enum TransportProcol {
    Tcp(TcpStream),
    UdpAssociate(UdpAssociate),
}

/// Connect hold data relevant to Connect command SOCKS5 proxying
pub struct Connect {
    pub inbound: TcpStream,
    pub outbound: TcpStream,
}

/// Connect implementation block
impl Connect {
    /// Connect run method
    pub async fn run(mut self) -> Result<()> {
        let (from_client, from_server) =
            // Relay between streams
            copy_bidirectional(&mut self.inbound, &mut self.outbound).await?;

        // DEBUG
        info!(
            "connection closed: {} bytes from client, {} bytes from server",
            from_client, from_server
        );

        Ok(())
    }
}

/// UdpAssociate holds data relevant to the UDP Associate command
/// such as SOCKS server socket and address as well as the target address
pub struct UdpAssociate {
    pub server_socket: UdpSocket,
    pub server_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub target_addr: SocketAddr,
}

/// UdpAssociate implementation block
impl UdpAssociate {
    /// UDP Associate run method
    pub async fn run(self, stream: &mut TcpStream) -> Result<()> {
        // SOCKS5 UDP Request Header
        // +----+------+------+----------+----------+----------+
        // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
        // +----+------+------+----------+----------+----------+
        // | 2  |  1   |  1   | Variable |    2     | Variable |
        // +----+------+------+----------+----------+----------+

        // Instantiate UDP relay buffer
        let mut buffer = [0u8; MAX_DGRAM];

        // Instantiate connection pool
        let mut outbound_sockets: HashMap<SocketAddr, UdpSocket> = HashMap::new();

        // Track last activity time for each client
        let mut last_activity: HashMap<SocketAddr, Instant> = HashMap::new();

        // Set a 60s timeout
        let timeout = Duration::from_secs(60);

        // DEBUG
        info!(
            "UDP relay started: server is listening on: {}",
            self.server_addr
        );

        loop {
            select! {
                // We need to monitor the TCP connection to handle teardown if needed
                tcp_check = stream.readable() => {
                    if tcp_check.is_err() {
                        info!("TCP connection error: terminating UDP association");
                        break;
                    }

                    let mut test_buf = [0u8; 1];
                    match stream.try_read(&mut test_buf) {
                        Ok(0) => {
                            info!("Client disconnected: terminating UDP association");
                            break;
                        },
                        Ok(_) => {
                             info!("Unexpected data on TCP connection during UDP association");
                        },
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // No data on TCP, totally fine
                        },
                        Err(e) => {
                            error!("[ERR] TCP read error: {}", e);
                            break;
                        }
                    }
                }

                // Client -> server
                incoming_udp = self.server_socket.recv_from(&mut buffer) => {
                    match incoming_udp {
                        Ok((len, client_addr)) =>  {
                            // TODO: write helper to parse incoming UDP and forward data
                            let _ = len;
                            let _ = client_addr;
                        },
                        Err(e) => {
                            error!("[ERR] UDP receive error: {e}");
                            break;
                        }
                    }
                }

                // TODO: Handle incoming from outbound
            }

            // TODO: Clean up expired connections
        }

        Ok(())
    }
}

/// handle_socks_request checks the incoming request for SOCKS5 version number
/// and command and routes the stream to the appropriate command handler
pub async fn handle_socks_request(stream: &mut TcpStream) -> Result<TransportProcol> {
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

    // Check command and route
    match Command::from_byte(command) {
        Some(Command::Connect) => {
            let outbound = handle_connect_cmd(stream).await?;
            Ok(TransportProcol::Tcp(outbound))
        }
        Some(Command::Bind) => {
            send_reply(stream, ReplyCode::CommandNotSupported, "0.0.0.0:0".parse()?).await?;
            Err(anyhow!("[ERR] BIND not supported"))
        }
        Some(Command::UdpAssociate) => {
            let udp_association = handle_udpassociate_cmd(stream).await?;
            Ok(TransportProcol::UdpAssociate(udp_association))
        }
        _ => {
            send_reply(stream, ReplyCode::ServerFailure, "0.0.0.0:0".parse()?).await?;
            Err(anyhow!("[ERR] unknown command"))
        }
    }
}

// ================
// CONNECT COMMAND
// ================

/// handle_connect_cmd handles incoming connection requests from a SOCKS client
/// parses the request, and returns an outbound stream to the target address
async fn handle_connect_cmd(stream: &mut TcpStream) -> Result<TcpStream> {
    // Retrieve target from request
    let (target, _) = parse_target_address(stream).await?;

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

/// handle_udpassociate_cmd parses the incoming UDP ASSOCIATE command, retrieves, and
/// returns the target address
async fn handle_udpassociate_cmd(stream: &mut TcpStream) -> Result<UdpAssociate> {
    // Retrieve target address from request
    let target_addr = match parse_target_address(stream).await {
        Ok((addr, AddressType::IPv4)) => addr.parse()?,
        Ok((addr, AddressType::IPv6)) => addr.parse()?,
        Ok((addr, AddressType::DomainName)) => tokio::net::lookup_host(&addr)
            .await?
            .next()
            .ok_or_else(|| anyhow!("[ERR] failed to resolve host: {}", addr))?,
        Err(e) => return Err(anyhow!("[ERR] failed to parse target address: {e}")),
    };

    // Bind UDP socket on SOCKS server
    match UdpSocket::bind("0.0.0.0:0").await {
        Ok(sock) => {
            // Get the socket address
            let udp_socket_addr = sock.local_addr()?;

            // Instantiate UdpAssociate for return
            let udp_association = UdpAssociate {
                server_socket: sock,
                server_addr: udp_socket_addr,
                peer_addr: stream.peer_addr()?,
                target_addr,
            };
            Ok(udp_association)
        }
        Err(e) => {
            // If there's an issue, it's with binding the UDP socket server side
            send_reply(stream, ReplyCode::ServerFailure, "0.0.0.0:0".parse()?).await?;
            Err(e.into())
        }
    }
}

// =========
// HELPERS
// =========

/// parse_target_address contains logic to parse the network address
/// from an incoming client connection request: IPv4, IPv6, or domain name
/// and returns the resultant address as a String
async fn parse_target_address(stream: &mut TcpStream) -> Result<(String, AddressType)> {
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
