//! A lightweight SOCKS5 proxy library
//!
//! # Example
//! ```no_run
//! use miniproxy::{Socks5Server, auth::UserPass};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let server = Socks5Server::new("127.0.0.1:1080");
//!     server.run().await?;
//!     Ok(())
//! }
//! ```

pub mod address;
pub mod auth;
pub mod commands;
pub mod protocol;
pub mod server;

// Re-export main types at crate root for convenience
pub use auth::UserPass;
pub use protocol::{AuthMethod, Command, ReplyCode, Version};
pub use server::Socks5Server;

// Re-export the transport enum if users need it
pub use commands::TransportProtocol;
