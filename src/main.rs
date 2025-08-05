pub mod socks5;
use anyhow::{Result, anyhow};
use clap::Parser;
use tokio::{
    io,
    net::{TcpListener, TcpStream},
};
use tracing::{error, info};

// TODO: add lib.rs

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
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt::init();

    // Parse args
    let args = Args::parse();

    match args.socks5 {
        true => proxy_socks(args.listen).await,
        false => {
            let target = args
                .target
                .ok_or_else(|| anyhow!("[ERR] target is required for TCP proxy mode"))?;
            proxy_tcp(args.listen, target).await
        }
    }
}

/// proxy_socks handles pass off from main to SOCKS5 proxy logic
async fn proxy_socks(listen_addr: String) -> Result<()> {
    // DEBUG
    info!("SOCKS5 proxy listening on {}", listen_addr);

    // Instantiate tokio listener
    let listener = TcpListener::bind(listen_addr).await?;

    // Listen for connections to proxy
    loop {
        // Accept incoming connection
        let (inbound, peer_addr) = listener.accept().await?;

        // Spawn async task
        tokio::spawn(async move {
            // DEBUG
            info!("new client: {}", peer_addr);

            // Send connection to connection handler
            if let Err(e) = socks5::server::handle_socks5(inbound).await {
                error!("connection error: {}", e);
            }
        });
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
