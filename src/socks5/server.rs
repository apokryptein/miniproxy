use crate::socks5::{
    auth::{self, UserPass},
    commands::{self, TransportProcol, UdpAssociate},
};
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
};
use tracing::{error, info};

/// Socks5Server represents a SOCKS5 server and houses related
/// configuration data
pub struct Socks5Server {
    pub listen_addr: String,
    pub auth_config: Option<Arc<UserPass>>,
}

/// Socks5Server implementation block
impl Socks5Server {
    /// new is a constructor for the Socks5Server type
    pub fn new(listen_addr: impl Into<String>) -> Self {
        Self {
            listen_addr: listen_addr.into(),
            auth_config: None,
        }
    }

    /// with_auth applies the desired authentication
    pub fn with_auth(mut self, auth: Option<UserPass>) -> Self {
        // Arc allows shared ownership of UserPass
        self.auth_config = auth.map(Arc::new);
        self
    }

    /// run handles server spinup and listens for incoming connections
    pub async fn run(&self) -> Result<()> {
        // DEBUG
        info!("SOCKS5 proxy listening on {}", &self.listen_addr);

        // Instantiate tokio listener
        let listener = TcpListener::bind(&self.listen_addr).await?;

        // Listen for connections to proxy
        loop {
            // Accept incoming connection
            let (inbound, peer_addr) = listener.accept().await?;

            // Clone for this connection
            let auth_config = self.auth_config.clone();

            // Spawn async task
            tokio::spawn(async move {
                // DEBUG
                info!("new client: {}", peer_addr);

                // Send connection to connection handler
                if let Err(e) = handle_connection(inbound, auth_config).await {
                    error!("connection error: {}", e);
                }
            });
        }
    }
}

/// handle_socks5 handles the full client/server SOCKS5 protocol flow
async fn handle_connection(
    mut stream: TcpStream,
    auth_config: Option<Arc<UserPass>>,
) -> Result<()> {
    // Negotiate authentication with client
    auth::negotiate_auth(&mut stream, &auth_config).await?;

    // Handle connection request from client
    match commands::handle_socks_request(&mut stream).await {
        Ok(TransportProcol::Tcp(tcp_outbound)) => {
            // Relay UDP traffic
            relay_tcp(stream, tcp_outbound).await?;
        }
        Ok(TransportProcol::UdpAssociate(udp_association)) => {
            // Relay UDP traffic
            relay_udp(&mut stream, &udp_association).await?;
        }
        Err(e) => {
            return Err(anyhow!("[ERR] failed to handle socks request: {e}"));
        }
    }

    Ok(())
}

/// relay_tcp bidrectionally streams data the data between them beween the client and target
async fn relay_tcp(mut inbound: TcpStream, mut outbound: TcpStream) -> Result<()> {
    let (from_client, from_server) = copy_bidirectional(&mut inbound, &mut outbound).await?;

    // DEBUG
    info!(
        "connection closed: {} bytes from client, {} bytes from server",
        from_client, from_server
    );

    Ok(())
}

/// relay_udp bidrectionally streams data data between a client and target
async fn relay_udp(tcp_control: &mut TcpStream, udp_associate: &UdpAssociate) -> Result<()> {
    // TODO: continue udp association impelementation here

    // +----+------+------+----------+----------+----------+
    // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    // +----+------+------+----------+----------+----------+
    // | 2  |  1   |  1   | Variable |    2     | Variable |
    // +----+------+------+----------+----------+----------+

    let (_, _) = (tcp_control, udp_associate);
    Ok(())
}
