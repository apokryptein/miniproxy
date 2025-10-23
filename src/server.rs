use crate::{
    auth::{self, UserPass},
    commands::{self, TransportProtocol},
};
use anyhow::{Result, anyhow};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

/// Socks5Server represents a SOCKS5 server and houses related
/// configuration data
pub struct Socks5Server {
    pub listen_addr: String,
    pub auth_config: Option<Arc<UserPass>>,
    listener: Option<TcpListener>,
}

/// Socks5Server implementation block
impl Socks5Server {
    /// new is a constructor for the Socks5Server type
    pub fn new(listen_addr: impl Into<String>) -> Self {
        Self {
            listen_addr: listen_addr.into(),
            auth_config: None,
            listener: None,
        }
    }

    /// with_auth applies the desired authentication
    pub fn with_auth(mut self, auth: Option<UserPass>) -> Self {
        // Arc allows shared ownership of UserPass
        self.auth_config = auth.map(Arc::new);
        self
    }

    /// bind to the listen address, panics when called twice
    pub async fn bind(&mut self) -> Result<SocketAddr> {
        if self.listener.is_some() {
            panic!("bind can only be called once");
        }

        // Instantiate tokio listener
        let listener = TcpListener::bind(&self.listen_addr).await?;
        let addr = listener.local_addr()?;

        // DEBUG
        info!("SOCKS5 proxy listening on {:?}", addr);

        self.listener = Some(listener);
        Ok(addr)
    }

    /// run handles server spinup and listens for incoming connections
    pub async fn run(&mut self) -> Result<()> {
        if self.listener.is_none() {
            self.bind().await?;
        }
        let listener = self.listener.take().unwrap();

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
        Ok(TransportProtocol::Tcp(tcp_outbound)) => {
            // Instantiate Connect
            let connect = commands::Connect {
                inbound: stream,
                outbound: tcp_outbound,
            };

            // Run it
            connect.run().await?;
        }
        Ok(TransportProtocol::UdpAssociate(udp_association)) => {
            // Relay UDP traffic
            udp_association.run(&mut stream).await?;
        }
        Err(e) => {
            return Err(anyhow!("[ERR] failed to handle socks request: {e}"));
        }
    }

    Ok(())
}
