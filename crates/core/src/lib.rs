pub mod address;
pub mod crypto;

pub use address::Socks5Addr;
use crypto::Cipher;

pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize - 16;
pub const TUN_MODE: u8 = 0x00;
pub const TUN_MTU: usize = 1400;
pub const TUN_CLIENT_IP: [u8; 4] = [10, 8, 0, 2];

pub struct Frame {
    cipher: Cipher,
}

impl Frame {
    pub fn new(password: &str, salt: &[u8]) -> Self {
        Self {
            cipher: Cipher::new(password, salt),
        }
    }

    pub fn salt_len() -> usize {
        Cipher::salt_len()
    }

    pub fn generate_salt() -> Vec<u8> {
        Cipher::generate_salt()
    }

    pub fn encode(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err("payload too large".into());
        }
        let nonce = Cipher::generate_nonce();
        let ciphertext = self.cipher.encrypt(&nonce, payload)?;
        let total_len = u16::try_from(ciphertext.len()).map_err(|_| "ciphertext too large")?;
        let mut frame = Vec::with_capacity(12 + 2 + ciphertext.len());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    pub fn decode(&self, frame: &[u8]) -> Result<(Vec<u8>, usize), String> {
        if frame.len() < 14 {
            return Err("frame too short".into());
        }
        let nonce = &frame[..12];
        let ct_len = u16::from_be_bytes([frame[12], frame[13]]) as usize;
        let ct_start = 14;
        if frame.len() < ct_start + ct_len {
            return Err("frame truncated".into());
        }
        let ciphertext = &frame[ct_start..ct_start + ct_len];
        let plain = self.cipher.decrypt(nonce, ciphertext)?;
        Ok((plain, ct_start + ct_len))
    }
}

pub fn validate_tun_packet(packet: &[u8]) -> Result<(), String> {
    validate_ipv4_packet(packet)?;
    if packet[12..16] != TUN_CLIENT_IP {
        return Err("invalid TUN source address".into());
    }
    Ok(())
}

pub fn validate_tun_response(packet: &[u8]) -> Result<(), String> {
    validate_ipv4_packet(packet)?;
    if packet[16..20] != TUN_CLIENT_IP {
        return Err("invalid TUN destination address".into());
    }
    Ok(())
}

fn validate_ipv4_packet(packet: &[u8]) -> Result<(), String> {
    if packet.len() < 20 || packet.len() > TUN_MTU {
        return Err("invalid IPv4 packet length".into());
    }
    if packet[0] >> 4 != 4 {
        return Err("not an IPv4 packet".into());
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < 20 || header_len > packet.len() {
        return Err("invalid IPv4 header length".into());
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len != packet.len() {
        return Err("invalid IPv4 total length".into());
    }
    Ok(())
}

pub fn pack_addr_payload(addr: &Socks5Addr, data: &[u8]) -> Vec<u8> {
    let mut payload = addr.to_bytes();
    payload.extend_from_slice(data);
    payload
}

pub fn unpack_addr_payload(data: &[u8]) -> Result<(Socks5Addr, &[u8]), String> {
    let (addr, consumed) = Socks5Addr::from_bytes(data)?;
    Ok((addr, &data[consumed..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_and_size_limit() {
        let frame = Frame::new("password", &[7; 32]);
        let payload = b"hello";
        let encoded = frame.encode(payload).unwrap();
        assert_eq!(frame.decode(&encoded).unwrap().0, payload);
        assert!(frame.encode(&vec![0; MAX_PAYLOAD_LEN + 1]).is_err());
    }

    #[test]
    fn validates_tun_packets() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[12..16].copy_from_slice(&TUN_CLIENT_IP);
        assert!(validate_tun_packet(&packet).is_ok());
        packet[16..20].copy_from_slice(&TUN_CLIENT_IP);
        assert!(validate_tun_response(&packet).is_ok());
        packet[12] = 192;
        assert!(validate_tun_packet(&packet).is_err());
    }

    #[test]
    fn address_payload_keeps_first_data() {
        let addresses = [
            Socks5Addr::IPv4([127, 0, 0, 1], 80),
            Socks5Addr::Domain("example.com".into(), 443),
            Socks5Addr::IPv6([0; 16], 53),
        ];
        for address in addresses {
            let payload = pack_addr_payload(&address, b"first data");
            let (decoded, data) = unpack_addr_payload(&payload).unwrap();
            assert_eq!(decoded.to_bytes(), address.to_bytes());
            assert_eq!(data, b"first data");
        }
    }
}
