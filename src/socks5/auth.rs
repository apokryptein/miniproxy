use crate::socks5::protocol::{AuthMethod, Version};
use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// negotiate_auth handles authentication negotiation between the SOCKS server and client
pub async fn negotiate_auth(stream: &mut TcpStream) -> Result<()> {
    // ClientHello format
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+

    // Instantiate handshake buffer & read
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    // Parse version and client methods from handshake
    let version = buf[0];
    let n_methods = buf[1];

    // Ensure version is 0x05 -> SOCKS5
    if version != Version::SOCKS5 as u8 {
        bail!("[ERR] not SOCKS5");
    }

    // Read auth methods: currently only implementing no-auth
    let mut methods = vec![0u8; n_methods as usize];
    stream.read_exact(&mut methods).await?;

    // Retrieve desired method
    let method = select_auth_method(&methods);

    // ServerChoice method selection reply format
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+

    // Write response to client
    stream.write_all(&[Version::SOCKS5 as u8, method]).await?;

    Ok(())
}

/// select_auth_method take a reference to a u8 byte array that contains
/// auth methods from the socks client. It then returns the desired
/// auth method's byte value
fn select_auth_method(client_methods: &[u8]) -> u8 {
    // Preferred auth method order
    // NOTE: update this as new methods are added -> user/pass, gssapi
    const PREFERRED_METHODS: &[AuthMethod] = &[AuthMethod::NoAuth];

    // Iterate through preferences in order. If there's a match
    // return it
    for &preferred in PREFERRED_METHODS {
        if client_methods.contains(&(preferred as u8)) {
            return preferred as u8;
        }
    }

    AuthMethod::NoAcceptable as u8
}

// TODO: add username/password authentication
