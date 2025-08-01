use crate::socks5::auth::negotiate_auth;
use crate::socks5::commands::handle_connect_request;
use anyhow::Result;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tracing::info;

/// handle_socks5 handles the full client/server SOCKS5 protocol flow
pub async fn handle_socks5(mut stream: TcpStream) -> Result<()> {
    // Negotiate authentication with client
    negotiate_auth(&mut stream).await?;

    // Handle connection requet from client
    let outbound = handle_connect_request(&mut stream).await?;

    // Proxy
    proxy_connections(stream, outbound).await?;

    Ok(())
}

/// proxy_connections takes inbound and outbounds streams and bidrectionally streams data
/// or "proxies" the data between them
async fn proxy_connections(mut inbound: TcpStream, mut outbound: TcpStream) -> Result<()> {
    let (from_client, from_server) = copy_bidirectional(&mut inbound, &mut outbound).await?;

    // DEBUG
    info!(
        "connection closed: {} bytes from client, {} bytes from server",
        from_client, from_server
    );

    Ok(())
}
