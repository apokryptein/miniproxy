use crate::address::{parse_address_from_packet, parse_address_from_stream};
use crate::protocol::{AddressType, Command, MAX_DGRAM, RSV, ReplyCode, Version};
use anyhow::{Result, anyhow, bail};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{io, net::SocketAddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpStream, UdpSocket},
    select,
    sync::RwLock,
};
use tracing::{debug, error, info};

/// TransportProcol is an enum holding either a tokio
/// TcpStream or UdpSocket
pub enum TransportProtocol {
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

/// UdpAssociationKey is the key for tracking UDP associations
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct UdpAssociationKey {
    client_addr: SocketAddr,
    target_addr: SocketAddr,
}

/// UdpRelayState stores the state for managing connections
struct UdpRelayState {
    /// Maps (client_addr, target_addr) -> outbound socket
    outbound_sockets: HashMap<UdpAssociationKey, Arc<UdpSocket>>,

    /// Track last activity for cleanup
    last_activity: HashMap<UdpAssociationKey, Instant>,
}

/// UdpRelayState implementation block
impl UdpRelayState {
    /// new is a UdpRelayState constructor
    fn new() -> Self {
        Self {
            outbound_sockets: HashMap::new(),
            last_activity: HashMap::new(),
        }
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
        // Send the successful reply with the bound UDP address
        send_reply(stream, ReplyCode::Succeeded, self.server_addr).await?;

        // Extract values before self move
        let peer_addr = self.peer_addr;

        // Wrap server in Arc to share across tasks
        let server_socket = Arc::new(self.server_socket);

        // Instantiate UDP relay buffer
        let mut buffer = [0u8; MAX_DGRAM];

        // Initialize relay state
        let relay_state = Arc::new(RwLock::new(UdpRelayState::new()));

        // Set a 60s timeout
        let timeout = Duration::from_secs(60);

        // Create channel for coordinating outbound socket responses
        let (response_tx, mut response_rx) = tokio::sync::mpsc::unbounded_channel();

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

                    // Insantiate buffer and attempt read from TCP stream
                    let mut test_buf = [0u8; 1];
                    match stream.try_read(&mut test_buf) {
                        Ok(0) => {
                            info!("Client disconnected: terminating UDP association");
                            break;
                        },
                        Ok(_) => {
                             debug!("Unexpected data on TCP connection during UDP association");
                        },
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // No data on TCP, totally fine
                        },
                        Err(e) => {
                            error!("TCP read error: {}", e);
                            break;
                        }
                    }
                }

                // Client -> server
                incoming_udp = server_socket.recv_from(&mut buffer) => {
                    match incoming_udp {
                        Ok((len, client_addr)) =>  {
                            // Validate client  -> client IP address must match
                            if !is_client_allowed(&client_addr, &peer_addr) {
                                error!("rejected UDP from unauthorized client: {client_addr}");
                                continue
                            }

                            // Clone relay_state and response_tx
                            let relay_state_clone = Arc::clone(&relay_state);
                            let response_tx = response_tx.clone();

                            // Grab packet from buffer
                            let packet = buffer[..len].to_vec();

                            // Spawn task to handle datagram
                            tokio::spawn(async move {
                                if let Err(e) = handle_client_datagram(
                                relay_state_clone,
                                packet,
                                client_addr,
                                response_tx,
                                ).await {
                                    error!("failed to handle client datagram from {client_addr}: {e}");
                                }
                            });
                        },
                        Err(e) => {
                            error!("UDP receive error: {e}");
                            break;
                        }
                    }
                }

                // Handle responses from target servers
                // Target -> Server -> Client
                Some((data, target_addr, client_addr)) = response_rx.recv() => {
                    // Update last activity
                    {
                        let mut state = relay_state.write().await;
                        let key = UdpAssociationKey { client_addr, target_addr };
                        state.last_activity.insert(key, Instant::now());
                    }

                    // Send response to client
                    if let Err(e) = send_response_to_client(
                        &server_socket,
                        &data,
                        target_addr,
                        client_addr
                    ).await {
                        error!("Error sending response to client {client_addr}: {e}");
                    }
                }

                // Clean up expired connections
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    cleanup_expired_connections(Arc::clone(&relay_state), timeout).await;
                }
            }
        }

        Ok(())
    }
}

/// handle_client_datagram handles parsing and forwarding of an incoming
/// UDP datagram from the SOCKS5 client
async fn handle_client_datagram(
    relay_state: Arc<RwLock<UdpRelayState>>,
    packet: Vec<u8>,
    client_addr: SocketAddr,
    response_tx: tokio::sync::mpsc::UnboundedSender<(Vec<u8>, SocketAddr, SocketAddr)>,
) -> Result<()> {
    // SOCKS5 UDP Request Header
    // +----+------+------+----------+----------+----------+
    // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    // +----+------+------+----------+----------+----------+
    // | 2  |  1   |  1   | Variable |    2     | Variable |
    // +----+------+------+----------+----------+----------+

    // Ensure we receive a valid packet
    if packet.len() < 4 {
        return Err(anyhow!("UDP packet too short"));
    }

    // Check for fragmentation
    if packet[2] != 0x00 {
        return Err(anyhow!("UDP fragmentation not supported"));
    }

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
    let data = packet[offset..].to_vec();

    // Create association key
    let key = UdpAssociationKey {
        client_addr,
        target_addr,
    };

    // Get existing socket or create new one if one doesn't exist for target address
    let outbound_socket = {
        let mut state = relay_state.write().await;

        match state.outbound_sockets.get(&key) {
            // If existing socket
            Some(socket) => Arc::clone(socket),
            // Otherwise, create new socket
            None => {
                // Create new outbound socket
                let new_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                let socket_addr = new_socket.local_addr()?;

                // DEBUG
                info!("Created new UDP relay: {client_addr} -> {target_addr} (via {socket_addr})");

                // Store associations
                state
                    .outbound_sockets
                    .insert(key.clone(), Arc::clone(&new_socket));

                // Spawn task to monitor socket for response
                let response_tx = response_tx.clone();
                let socket_clone = Arc::clone(&new_socket);
                let target_addr_clone = target_addr;
                let client_addr_clone = client_addr;

                tokio::spawn(async move {
                    monitor_outbound_socket(
                        socket_clone,
                        target_addr_clone,
                        client_addr_clone,
                        response_tx,
                    )
                    .await;
                });

                new_socket
            }
        }
    };

    // Forward to target
    outbound_socket.send_to(&data, target_addr).await?;

    // Update last activity for socket
    {
        let mut state = relay_state.write().await;
        state.last_activity.insert(key, Instant::now());
    }

    // DEBUG
    debug!(
        "forwarded {} bytes: {client_addr} -> {target_addr}",
        data.len()
    );

    Ok(())
}

/// monitor_outbound_socket monitors an outbound socket for responses from the target
async fn monitor_outbound_socket(
    socket: Arc<UdpSocket>,
    target_addr: SocketAddr,
    client_addr: SocketAddr,
    response_tx: tokio::sync::mpsc::UnboundedSender<(Vec<u8>, SocketAddr, SocketAddr)>,
) {
    // Instantiate buffer
    let mut buffer = [0u8; MAX_DGRAM];

    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((len, from_addr)) => {
                // Verify response is from expected target
                if from_addr != target_addr {
                    error!("Unexpected response from {from_addr} (expected {target_addr})");
                    continue;
                }

                // Grab data
                let data = buffer[..len].to_vec();

                // Send through channel to main loop
                if response_tx.send((data, from_addr, client_addr)).is_err() {
                    // Channel closed, exit monitor
                    break;
                }

                // DEBUG
                debug!("Received {len} bytes from {from_addr} (expected: {target_addr})");
            }
            Err(e) => {
                error!("Error receiving from outbound socket: {e}");
                break;
            }
        }
    }

    // DEBUG
    debug!("Stopped monitoring socket for {client_addr} -> {target_addr}");
}

/// handle_socks_request checks the incoming request for SOCKS5 version number
/// and command and routes the stream to the appropriate command handler
pub async fn handle_socks_request(stream: &mut TcpStream) -> Result<TransportProtocol> {
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
            Ok(TransportProtocol::Tcp(outbound))
        }
        Some(Command::Bind) => {
            send_reply(stream, ReplyCode::CommandNotSupported, "0.0.0.0:0".parse()?).await?;
            Err(anyhow!("[ERR] BIND not supported"))
        }
        Some(Command::UdpAssociate) => {
            let udp_association = handle_udpassociate_cmd(stream).await?;
            Ok(TransportProtocol::UdpAssociate(udp_association))
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
async fn cleanup_expired_connections(relay_state: Arc<RwLock<UdpRelayState>>, timeout: Duration) {
    // Get current instant
    let now = Instant::now();

    let mut state = relay_state.write().await;

    let mut to_remove = Vec::new();

    // Find expired connections
    for (key, last_time) in state.last_activity.iter() {
        if now.duration_since(*last_time) > timeout {
            to_remove.push(key.clone());
        }
    }

    // Remove expired connections
    for key in to_remove {
        state.outbound_sockets.remove(&key);
        state.last_activity.remove(&key);

        info!(
            "Removed expired UDP relay: {} -> {}",
            key.client_addr, key.target_addr
        );
    }
}

/// create_response_packet build a SOCKS5 response packet
fn create_response_packet(data: &[u8], from_addr: SocketAddr) -> Result<Vec<u8>> {
    //  +----+------+------+----------+----------+----------+
    //  |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    //  +----+------+------+----------+----------+----------+
    //  | 2  |  1   |  1   | Variable |    2     | Variable |
    //  +----+------+------+----------+----------+----------+

    // Instantiate new vec for packet
    let mut packet = Vec::new();

    // RSV -> 2 bytes
    packet.extend_from_slice(&[0x00, 0x00]);

    // FRAG -> single byte
    packet.push(0x00);

    // Add address data bytes on type
    match from_addr {
        SocketAddr::V4(v4_addr) => {
            // ATYP -> 1 byte
            packet.push(AddressType::IPv4 as u8);

            // Address -> 4 bytes
            packet.extend_from_slice(&v4_addr.ip().octets());

            // Port in BE -> 2 bytes
            packet.extend_from_slice(&v4_addr.port().to_be_bytes());
        }
        SocketAddr::V6(v6_addr) => {
            // ATYP -> 1 byte
            packet.push(AddressType::IPv6 as u8);

            // Address -> 16 bytes
            packet.extend_from_slice(&v6_addr.ip().octets());

            // Port in BE -> 2 bytes
            packet.extend_from_slice(&v6_addr.port().to_be_bytes());
        }
    }

    // Push data onto packet
    packet.extend_from_slice(data);

    Ok(packet)
}

/// Send a response packet back to the client
async fn send_response_to_client(
    server_socket: &UdpSocket,
    data: &[u8],
    target_addr: SocketAddr,
    client_addr: SocketAddr,
) -> Result<()> {
    // Build SOCKS5 UDP response packet
    let response = create_response_packet(data, target_addr)?;

    // Send to client
    server_socket.send_to(&response, client_addr).await?;

    debug!(
        "Sent {} bytes from {} to client {}",
        data.len(),
        target_addr,
        client_addr
    );

    Ok(())
}

// Checks if the client is permitted to send UDP data to the alotted socket
// As per the SOCKS5 protocol, the IP address must match the IP address from the
// TCP connection.
fn is_client_allowed(client_addr: &SocketAddr, peer_addr: &SocketAddr) -> bool {
    client_addr.ip() == peer_addr.ip()
}
