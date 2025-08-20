//! Basic SOCKS5 server example

use miniproxy::Socks5Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let server = Socks5Server::new("127.0.0.1:1080");
    println!("Starting SOCKS5 server on 127.0.0.1:1080");

    server.run().await?;
    Ok(())
}
