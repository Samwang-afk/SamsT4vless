#[derive(Debug, Clone)]
pub enum Socks5Addr {
    IPv4([u8; 4], u16),
    Domain(String, u16),
    IPv6([u8; 16], u16),
}

impl Socks5Addr {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Socks5Addr::IPv4(addr, port) => {
                buf.push(0x01);
                buf.extend_from_slice(addr);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Socks5Addr::Domain(domain, port) => {
                buf.push(0x03);
                let domain_bytes = domain.as_bytes();
                buf.push(domain_bytes.len() as u8);
                buf.extend_from_slice(domain_bytes);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Socks5Addr::IPv6(addr, port) => {
                buf.push(0x04);
                buf.extend_from_slice(addr);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), String> {
        if data.is_empty() {
            return Err("empty address data".into());
        }
        let atyp = data[0];
        match atyp {
            0x01 => {
                if data.len() < 7 {
                    return Err("IPv4 address too short".into());
                }
                let mut addr = [0u8; 4];
                addr.copy_from_slice(&data[1..5]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                Ok((Socks5Addr::IPv4(addr, port), 7))
            }
            0x03 => {
                if data.len() < 2 {
                    return Err("domain address too short".into());
                }
                let len = data[1] as usize;
                let end = 2 + len + 2;
                if data.len() < end {
                    return Err("domain address truncated".into());
                }
                let domain = String::from_utf8_lossy(&data[2..2 + len]).to_string();
                let port = u16::from_be_bytes([data[2 + len], data[2 + len + 1]]);
                Ok((Socks5Addr::Domain(domain, port), end))
            }
            0x04 => {
                if data.len() < 19 {
                    return Err("IPv6 address too short".into());
                }
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&data[1..17]);
                let port = u16::from_be_bytes([data[17], data[18]]);
                Ok((Socks5Addr::IPv6(addr, port), 19))
            }
            _ => Err(format!("unknown address type: {}", atyp)),
        }
    }
}
