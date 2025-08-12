/// RSV: Fields marked RESERVED (RSV) must be set to X'00'.
pub const RSV: u8 = 0x00;

/// UDP_RSV: 2-byte RESERVED (RSV) field in UDP datagram header
pub const UDP_RSV: u8 = 0x0000;

/// UDP_FRAG: 1-byte fragment number value in the SOCKS5 UDP header
/// Set to 0x00 to let UDP handle any fragmentation
pub const UDP_FRAG: u8 = 0x00;

/// MAX_DRGRAM: maximum UDP datagram size in bytes
/// IPv4 maximum packet size (65,535) - IPv4 header size (20) - UDP header size (8) -> 65,507 bytes
pub const MAX_DGRAM: usize = 65_507;

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

/// AuthStatus represents the possible authentication reponse codes
/// for the SOCKS5 protocol
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthStatus {
    Success = 0x00,
    Failure = 0x01,
}

/// AuthMethod represents available SOCKS5
/// authentication methods
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthMethod {
    NoAuth = 0x00,
    // Gssapi = 0x01, not yet implemented
    UserPass = 0x02,
    // 0x03 - 0x7f: IANA reserved
    // 0x80 - 0xFE: private methods
    NoAcceptable = 0xFF,
}

/// AuthMethod implementation block
impl AuthMethod {
    /// from_byte converts a byte value to its associated AuthMethod
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => AuthMethod::NoAuth,
            0x02 => AuthMethod::UserPass,
            0xFF => AuthMethod::NoAcceptable,
            _ => AuthMethod::NoAcceptable,
        }
    }
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
