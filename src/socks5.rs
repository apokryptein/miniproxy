/// ClientHello represents a SOCKS5 client hello
struct ClientHello {
    /// SOCKS version -> 0x05
    version: u8,

    /// Vector of SOCKS5 authentication methods supported by client
    auth_methods: Vec<u8>,
}

/// ServerChoice represents the server's auth method selection
struct ServerChoice {
    /// SOCKS version -> 0x05
    version: u8,

    /// Authentication method selected by server
    method: u8,
}


/// ConnectRequest represents a client client connection request
struct ConnectRequest {
    /// SOCKS version -> 0x05
    version: u8,

    /// SOCKS5 command (connect, bind)
    command: u8,    // 0x01=connect
    
    /// Must be set to 0x00 as per specification
    reserved: u8,

    /// Address type (IPv4, domain, IPv6)
    addr_type: u8,  // 0x01=IPv4, 0x03=domain
    
    /// Destination address
    addr: Address,

    /// Destination port
    port: u16,
}
