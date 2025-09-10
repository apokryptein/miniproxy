# soxide

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight, fast SOCKS5 proxy library and server.

## Features

- SOCKS5 (RFC 1928) Implementation:
  - CONNECT command for TCP proxying
  - UDP ASSOCIATE for UDP relay
  - Username/Password authentication
  - No authentication
  - IPv4, IPv6, and domain name support
- Domain resolution happens proxy-side
- Built on Tokio for async I/O
- No dependencies on external proxy libraries
- Use as a library or standalone binary

## Installation

### Library

Add to your `Cargo.toml`:

```toml
[dependencies]
soxide = { git = "https://github.com/apokryptein/soxide" }
```

### Binary

Install the latest version from GitHub:

```sh
cargo install --git https://github.com/apokryptein/soxide
```

Or clone and build locally:

```sh
git clone https://github.com/apokryptein/soxide
cd soxide
cargo install --path <path>
```

## Usage

### Command Line

#### Basic proxy server (no authentication)

```sh
soxide --listen 127.0.0.1:1080
# or
soxide -l 127.0.0.1:1080
```

#### Username/password authentication

```sh
soxide -l 127.0.0.1:1080 --username <user> --password <pass>
# or
soxide -l 127.0.0.1:1080 -u <user> -p <pass>
```

#### Enable verbose logging

```sh
soxide -l 127.0.0.1:1080 -v
```

### Library Usage

#### Basic Server

```rust
use soxide::Socks5Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let server = Socks5Server::new("127.0.0.1:1080");
  server.run().await?;
  Ok(())
}
```

#### With Authentication

```rust
use soxide::{Socks5Server, auth::UserPass};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let auth = UserPass {
    username: "<user>".to_string(),
    password: "<pass>".to_string(),
  };

  let server = Socks5Server::new("127.0.0.1:1080")
    .with_auth(Some(auth));

  server.run().await?;
  Ok(())
}
```

## SOCKS5 Implementation Status

### Implemented

| Feature                  | Status        | Notes                               |
| ------------------------ | ------------- | ----------------------------------- |
| CONNECT                  | Full support  | RFC 1928                            |
| UDP ASSOCIATE            | Full Support  | RFC 1928                            |
| No Authentication        | Full Support  | RFC 1928                            |
| Username/Password        | Full Support  | RFC 1929                            |
| IPv4, IPv6, Domain Names | Full Support  | RFC 1928                            |
| BIND                     | Not supported | Rarely used - unlikely to implement |
| GSSAPI Authentication    | Not supported | Future feature                      |
