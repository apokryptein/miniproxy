use crate::protocol::{AuthMethod, AuthStatus, Version};
use anyhow::{Result, anyhow, bail};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::debug;

/// UserPass holds username/password credentials as dictated
/// server-side
#[derive(Clone)]
pub struct UserPass {
    pub username: String,
    pub password: String,
}

/// negotiate_auth handles authentication negotiation between the SOCKS server and client
pub async fn negotiate_auth(
    stream: &mut TcpStream,
    auth_config: &Option<Arc<UserPass>>,
) -> Result<()> {
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
        bail!("not SOCKS5");
    }

    // Read auth methods: currently only implementing no-auth
    let mut methods = vec![0u8; n_methods as usize];
    stream.read_exact(&mut methods).await?;

    // Retrieve desired method
    let method = select_auth_method(&methods, auth_config.is_some());

    // Write response to client with selected method
    stream.write_all(&[Version::SOCKS5 as u8, method]).await?;

    // If no accpetable methods, close connection
    if method == AuthMethod::NoAcceptable as u8 {
        bail!("no acceptable authentication methods");
    }

    // Route to appropriate auth handler
    match AuthMethod::from_byte(method) {
        AuthMethod::UserPass => {
            let creds = auth_config
                .as_ref()
                .ok_or_else(|| anyhow!("username/password required but not configured"))?;
            authenticate_userpass(stream, creds).await?
        }
        AuthMethod::NoAuth => {
            // Only allow NoAuth if auth isn't configured
            if auth_config.is_some() {
                bail!("authentication required but client didn't provide credentials");
            }
        }
        _ => bail!("unsupported authentication method"),
    }

    Ok(())
}

/// authenticate_userpass handles username/password authentication according to the RFC1929
async fn authenticate_userpass(stream: &mut TcpStream, server_creds: &UserPass) -> Result<()> {
    // Client Username/Password Request
    // +----+------+----------+------+----------+
    // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    // +----+------+----------+------+----------+
    // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    // +----+------+----------+------+----------+

    // Get subnegotiation -> 0x01 expected
    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver).await?;

    // Check version number
    if ver[0] != 0x01 {
        bail!("invalid username/password sugnegotiation number");
    }

    // Instantiate buffer & read username length
    let mut username_len = [0u8; 1];
    stream.read_exact(&mut username_len).await?;

    // Read username
    let mut username = vec![0u8; username_len[0] as usize];
    stream.read_exact(&mut username).await?;

    // Read password length
    let mut password_len = [0u8; 1];
    stream.read_exact(&mut password_len).await?;

    // Read password
    let mut password = vec![0u8; password_len[0] as usize];
    stream.read_exact(&mut password).await?;

    // Convert username/password to str for comparison
    let user_string = str::from_utf8(&username)?;
    let pass_string = str::from_utf8(&password)?;

    // Validate credentials
    let status = if user_string != server_creds.username || pass_string != server_creds.password {
        AuthStatus::Failure
    } else {
        AuthStatus::Success
    };

    // Username/Password Server response
    // +----+--------+
    // |VER | STATUS |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+

    // Write response to client with selected method
    stream.write_all(&[0x01, status as u8]).await?;

    // Validate authentication status
    match status {
        AuthStatus::Success => {
            debug!("authentication successful");
            Ok(())
        }
        AuthStatus::Failure => bail!("authentication failed"),
    }
}

/// select_auth_method take a reference to a u8 byte array that contains
/// auth methods from the socks client. It then returns the desired
/// auth method's byte value
fn select_auth_method(client_methods: &[u8], auth_required: bool) -> u8 {
    // Get necessary booleans for comparison
    let has_noauth = client_methods.contains(&(AuthMethod::NoAuth as u8));
    let has_userpass = client_methods.contains(&(AuthMethod::UserPass as u8));

    // Determine auth based on requirements and support
    match (auth_required, has_noauth, has_userpass) {
        (true, _, true) => AuthMethod::UserPass as u8, // Auth required, supported by client
        (false, true, _) => AuthMethod::NoAuth as u8,  // No auth required, supported by client
        (false, false, true) => AuthMethod::UserPass as u8, // No auth required, client only has userpass
        _ => AuthMethod::NoAcceptable as u8,                // No compatible methods
    }
}
