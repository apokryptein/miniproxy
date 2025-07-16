# miniproxy

A lighweight, fast TCP and SOCKS5 proxy written in Rust. Built for learning
and practical use.

## Features

- Dual mode: TCP port forwarding and SOCKS5 proxy
- SOCKS5 support: full CONNECT implementation (RFC 1928)
- DNS privacy: domain resolution happens proxy-side
- Async: built on Tokio for high performance
- Simple: no dependencies on external proxy libraries

## Installation

```sh
# Clone the repo
git clone https://github.com/apokryptein/miniproxy
cd miniproxy

# Build and install
cargo install --path <path>
```

## Usage

### TCP Proxy

```sh
miniproxy --listen 127.0.0.1:1080 --target example.com

miniproxy -l 127.0.0.1:1080 -t example.com
```

### SOCKS5 Proxy

```sh
miniproxy --listen 127.0.0.1:1080 --socks5

miniproxy -l 127.0.0.1:1080 -s
```

## SOCKS5 Implementation

### Supported Features
- CONNECT command
- IPv4 addresses
- IPv6 addresses
- Domain names
- No authentication

### Not Implemented (Future Improvements)
- BIND command
- UDP ASSOCIATE
- Username/password authentication


