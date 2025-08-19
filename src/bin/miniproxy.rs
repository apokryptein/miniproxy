use anyhow::{Result, bail};
use clap::Parser;
use miniproxy::{Socks5Server, auth::UserPass};
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about = "A lightweight TCP and SOCKS5 proxy", long_about = None)]
struct Args {
    /// Listener address
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    listen: String,

    /// Username for SOCKS5 proxy
    #[arg(short, long)]
    username: Option<String>,

    /// Password for SOCKS5 proxy
    #[arg(short, long)]
    password: Option<String>,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse args
    let args = Args::parse();

    // Initialize tracing subscriber
    let level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt().with_max_level(level).init();

    // Check for auth and grab it if present
    let auth = match (args.username, args.password) {
        (Some(u), Some(p)) => {
            info!("Authentication enabled");
            Some(UserPass {
                username: u,
                password: p,
            })
        }
        (None, None) => None,
        _ => bail!("[ERR] must provide both username and password (or neither)"),
    };

    // Instantiate server
    let server = Socks5Server::new(args.listen).with_auth(auth);

    // Run it
    info!("Starting SOCKS5 proxy: {}", server.listen_addr);
    server.run().await
}
