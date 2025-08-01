// These structs help to document the SOCKS5 protocol structure
// but aren't used in this implementation for simplicity

// ClientHello represents a SOCKS5 client hello
// struct ClientHello {
//     /// SOCKS version -> 0x05
//     version: u8,
//
//     /// Vector of SOCKS5 authentication methods supported by client
//     auth_methods: Vec<u8>,
// }
//
// /// ServerChoice represents the server's auth method selection
// struct ServerChoice {
//     /// SOCKS version -> 0x05
//     version: u8,
//
//     /// Authentication method selected by server
//     method: u8,
// }

// ConnectRequest represents a client connection request
// struct ConnectRequest {
//     /// SOCKS version -> 0x05
//     version: u8,
//
//     /// SOCKS5 command (connect, bind)
//     command: u8, // 0x01=connect
//
//     /// Must be set to 0x00 as per specification
//     reserved: u8,
//
//     /// Address type (IPv4, domain, IPv6)
//     addr_type: u8, // 0x01=IPv4, 0x03=domain
//
//     /// Destination address
//     addr: Address,
//
//     /// Destination port
//     port: u16,
// }

// Address represents a network address or domain to be used as the
// SOCKS5 target address
// #[derive(Debug, Clone)]
// enum Address {
//     IPv4([u8; 4]),
//     DomainName(String),
//     IPv6([u8; 16]),
// }

// RSV: Fields marked RESERVED (RSV) must be set to X'00'.
pub const RSV: u8 = 0x00;

/// AddressType represents the SOCKS5 address types:
/// IPv4, Domain Name, IPv6
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddressType {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04,
}

/// AddressType implementation block
impl AddressType {
    /// from_byte converts a byte to its related network address type
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(AddressType::IPv4),
            0x03 => Some(AddressType::DomainName),
            0x04 => Some(AddressType::IPv6),
            _ => None,
        }
    }
}

/// Version represents available SOCKS proxy versions
/// I included this for readability and clarity, but this
/// implementation only supports SOCKS5
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Version {
    SOCKS5 = 0x05,
}

/// AuthMethod represents available SOCKS5
/// authentication methods
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthMethod {
    NoAuth = 0x00,
    // Gssapi = 0x01, not yet implemented
    // UserPass = 0x02, note yet implemented
    // 0x03 - 0x7f: IANA reserved
    // 0x80 - 0xFE: private methods
    NoAcceptable = 0xFF,
}

/// Command represents SOCKS5 protocol commands
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

/// Command implementation block
impl Command {
    /// from_byte converts a byte to its related SOCKS5 protocol command
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Command::Connect),
            0x02 => Some(Command::Bind),
            0x03 => Some(Command::UdpAssociate),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReplyCode {
    Succeeded = 0x00,
    ServerFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    //TtlExpired = 0x06, // TODO: implement optional TTL on connection
    CommandNotSupported = 0x07,
    //AddrTypeUnsupported = 0x08,
    // 0x09 - 0xFF: unassigned
}
