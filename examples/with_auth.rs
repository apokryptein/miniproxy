//! SOCKS5 server with username/password authentication example

use miniproxy::{Socks5Server, auth::UserPass};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let auth = UserPass {
        username: "<user>".to_string(),
        password: "<pass>".to_string(),
    };

    let server = Socks5Server::new("127.0.0.1:1080").with_auth(Some(auth));

    server.run().await?;
    Ok(())
}
