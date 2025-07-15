pub mod socks5;
use anyhow::Result;
use clap::Parser;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Listen address
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    listen: String,

    // Target address
    #[arg(short, long)]
    target: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt::init();

    // Parse args
    let args = Args::parse();

    // DEBUG
    info!("Proxy listening on {} ->  {}", args.listen, args.target);

    // Instantiate tokio listener
    let listener = TcpListener::bind(args.listen).await?;

    // Listen for connections to proxy
    loop {
        // Accept incoming connection
        let (inbound, peer_addr) = listener.accept().await?;

        // Clone target address
        let target_addr = args.target.clone();

        // Spawn async task
        tokio::spawn(async move {
            // DEBUG
            info!("[INFO] new client: {}", peer_addr);

            // Send connection to connection handler
            if let Err(e) = handle_connection(inbound, &target_addr).await {
                error!("[ERR] connection error: {}", e);
            }
        });
    }
}

// TCP connection handler
// handle_connection handles a given TCP connection by copying data bidirectional between the
// client and target server
async fn handle_connection(mut inbound: TcpStream, target_addr: &str) -> Result<()> {
    // Connect to target
    let mut outbound = TcpStream::connect(target_addr).await?;

    // Use tokio to handle bidirectional streaming
    let (bytes_out, bytes_in) = io::copy_bidirectional(&mut inbound, &mut outbound).await?;

    // DEBUG
    info!(
        "[INFO] connection closed. Sent: {}, Received: {}",
        bytes_out, bytes_in
    );

    Ok(())
}
