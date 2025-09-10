//! A lightweight SOCKS5 proxy library
//!
//! ## SOCKS5 Implementation
//!
//! - Features:
//!     - CONNECT
//!     - UDP ASSOCIATE
//!     - No Authentication
//!     - Username/Passowrd Authentication
//!     - Async using tokio and channel-based communication
//!     - Stateful tracking of client-target associations
//!     - Dedicated socket per client-target pair -> minimizes NAT and client identification issues
//!     - Time-out based socket cleanup
//! - [SOCKS5 (RFC 1928)](https://datatracker.ietf.org/doc/html/rfc1928)
//! - [Username/Password Authentication (RFC 1929)](https://datatracker.ietf.org/doc/html/rfc1929)
//!
//! # Example
//! ```no_run
//! use soxide::{Socks5Server, auth::UserPass};
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
