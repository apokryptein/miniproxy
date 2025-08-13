use crate::socks5::address::{parse_address_from_packet, parse_address_from_stream};
use crate::socks5::protocol::{AddressType, Command, MAX_DGRAM, RSV, ReplyCode, Version};
use anyhow::{Result, anyhow, bail};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::{io, net::SocketAddr};
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
                            // Parse datagram and relay data
                            if let Err(e) = self.handle_datagram(&mut outbound_sockets, &mut last_activity, &buffer[..len], client_addr).await {
                                error!("[ERR] failed to handle client datagram: {e}");
                            }
                        },
                        Err(e) => {
                            error!("[ERR] UDP receive error: {e}");
                            break;
                        }
                    }
                }

                // TODO: Handle incoming from outbound


                // Clean up expired connections
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    clean_expired_connections(&mut outbound_sockets, &mut last_activity, timeout);
                }
            }
        }

        Ok(())
    }

    /// handle_datagram handles parsing and forwarding of an incoming
    /// UDP datagram from the SOCKS5 client
    async fn handle_datagram(
        &self,
        outbound_sockets: &mut HashMap<SocketAddr, UdpSocket>,
        last_activity: &mut HashMap<SocketAddr, Instant>,
        packet: &[u8],
        client_addr: SocketAddr,
    ) -> Result<()> {
        // SOCKS5 UDP Request Header
        // +----+------+------+----------+----------+----------+
        // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
        // +----+------+------+----------+----------+----------+
        // | 2  |  1   |  1   | Variable |    2     | Variable |
        // +----+------+------+----------+----------+----------+

        // Get address type directly -> skip RSV and FRAG
        let atyp = packet[3];

        // Set offset -> starts after ATYP
        let mut offset = 4;

        // Parse target address from packet
        let (target_addr, addr_len) = parse_address_from_packet(&packet, offset, atyp).await?;

        // Update offset to push past dest addr and port
        offset += addr_len;

        // Ensure there is data in the packet
        if offset >= packet.len() {
            return Err(anyhow!("no data in UDP packet"));
        }

        // Pull out data for forwarding
        let data = &packet[offset..];

        // Get existing socket or create new one if one doesn't exist for target address
        let outbound_socket = match outbound_sockets.get(&target_addr) {
            Some(socket) => socket,
            None => {
                // Bind new socket
                let new_socket = UdpSocket::bind("0.0.0.0:0").await?;

                // DEBUG
                info!("created new outbound socket {target_addr}");

                // Add to outboudn_sockets HashMap
                outbound_sockets.insert(target_addr, new_socket);

                outbound_sockets.get(&target_addr).unwrap()
            }
        };

        // Forward to target
        outbound_socket.send_to(data, target_addr).await?;

        // Update last activity for socket
        last_activity.insert(target_addr, Instant::now());

        // DEBUG
        info!(
            "forwarded {} bytes from {client_addr} to {target_addr}",
            data.len()
        );

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
    let (target, _) = parse_address_from_stream(stream).await?;

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
    let target_addr = match parse_address_from_stream(stream).await {
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

/// clean_expired_connections removes expired outbound connections from last_activity
/// and outbound_sockets hash maps
fn clean_expired_connections(
    outbound_sockets: &mut HashMap<SocketAddr, UdpSocket>,
    last_activity: &mut HashMap<SocketAddr, Instant>,
    timeout: Duration,
) {
    // Get current instant
    let now = Instant::now();

    // Remove expired entries from last_activity
    last_activity.retain(|&addr, &mut last_time| {
        let is_expired = now.duration_since(last_time) > timeout;
        if is_expired {
            // Also remove from outbound_sockets
            outbound_sockets.remove(&addr);

            // DEBUG
            info!("removed expired connection to {addr}");

            // Remove from last_activity
            false
        } else {
            // Leave in last_activity
            true
        }
    });
}
