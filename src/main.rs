pub mod socks5;
use anyhow::{Result, anyhow, bail};
use clap::Parser;
use tokio::{
    io,
    net::{TcpListener, TcpStream},
};
use tracing::{error, info};

use crate::socks5::{auth::UserPass, server::Socks5Server};

#[derive(Parser, Debug)]
#[command(author, version, about = "A lightweight TCP and SOCKS5 proxy", long_about = None)]
struct Args {
    /// Listener address
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    listen: String,

    /// Target address
    #[arg(short, long)]
    target: Option<String>,

    /// Enable SOCKS5 proxy mode
    #[arg(short, long, action)]
    socks5: bool,

    /// Username for SOCKS5 proxy
    #[arg(short, long)]
    username: Option<String>,

    /// Password for SOCKS5 proxy
    #[arg(short, long)]
    password: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt::init();

    // Parse args
    let args = Args::parse();

    // Check for auth and grab it if present
    let auth = match (args.username, args.password) {
        (Some(u), Some(p)) => Some(UserPass {
            username: u,
            password: p,
        }),
        (None, None) => None,
        _ => bail!("[ERR] must provide both username and password (or neither)"),
    };

    // Check for socks5
    match args.socks5 {
        true => {
            // Instantiate new Socks5Server
            let server = Socks5Server::new(args.listen).with_auth(auth);

            // Run it
            server.run().await
        }
        false => {
            let target = args
                .target
                .ok_or_else(|| anyhow!("[ERR] target is required for TCP proxy mode"))?;
            proxy_tcp(args.listen, target).await
        }
    }
}

/// proxy_tcp handles simple TCP proxy logic
async fn proxy_tcp(listen_addr: String, target_addr: String) -> Result<()> {
    // DEBUG
    info!("proxy listening on {} -> {}", listen_addr, target_addr);

    // Instantiate tokio listener
    let listener = TcpListener::bind(listen_addr).await?;

    // Listen for connections to proxy
    loop {
        // Accept incoming connection
        let (inbound, peer_addr) = listener.accept().await?;

        // Clone target address
        let target_addr = target_addr.clone();

        // Spawn async task
        tokio::spawn(async move {
            // DEBUG
            info!("new client: {}", peer_addr);

            // Send connection to connection handler
            if let Err(e) = handle_tcp_connection(inbound, &target_addr).await {
                error!("[ERR] connection error: {}", e);
            }
        });
    }
}

// TCP connection handler
// handle_connection handles a given TCP connection by copying data bidirectional between the
// client and target server
async fn handle_tcp_connection(mut inbound: TcpStream, target_addr: &str) -> Result<()> {
    // Connect to target
    let mut outbound = TcpStream::connect(target_addr).await?;

    // Use tokio to handle bidirectional streaming
    let (bytes_out, bytes_in) = io::copy_bidirectional(&mut inbound, &mut outbound).await?;

    // DEBUG
    info!(
        "connection closed. Sent: {}, Received: {}",
        bytes_out, bytes_in
    );

    Ok(())
}
