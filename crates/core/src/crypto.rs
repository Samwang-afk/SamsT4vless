use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};

const SALT_LEN: usize = 32;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub struct Cipher {
    key: LessSafeKey,
}

impl Cipher {
    pub fn new(password: &str, salt: &[u8]) -> Self {
        let mut key_bytes = [0u8; KEY_LEN];
        hkdf::Salt::new(hkdf::HKDF_SHA256, salt)
            .extract(password.as_bytes())
            .expand(&[b"ss-subkey"], &CHACHA20_POLY1305)
            .unwrap()
            .fill(&mut key_bytes)
            .unwrap();
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap();
        Self {
            key: LessSafeKey::new(unbound),
        }
    }

    pub fn salt_len() -> usize {
        SALT_LEN
    }

    pub fn nonce_len() -> usize {
        NONCE_LEN
    }

    pub fn tag_len() -> usize {
        TAG_LEN
    }

    pub fn generate_salt() -> Vec<u8> {
        let rng = SystemRandom::new();
        let mut salt = vec![0u8; SALT_LEN];
        rng.fill(&mut salt).unwrap();
        salt
    }

    pub fn generate_nonce() -> [u8; NONCE_LEN] {
        let rng = SystemRandom::new();
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill(&mut nonce).unwrap();
        nonce
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = Nonce::assume_unique_for_key(
            nonce
                .try_into()
                .map_err(|e| format!("bad nonce: {:?}", e))?,
        );
        let mut buffer = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer)
            .map_err(|e| format!("encrypt error: {}", e))?;
        Ok(buffer)
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < TAG_LEN {
            return Err("ciphertext too short".into());
        }
        let nonce = Nonce::assume_unique_for_key(
            nonce
                .try_into()
                .map_err(|e| format!("bad nonce: {:?}", e))?,
        );
        let mut buffer = ciphertext.to_vec();
        self.key
            .open_in_place(nonce, Aad::empty(), &mut buffer)
            .map_err(|e| format!("decrypt error: {}", e))?;
        buffer.truncate(buffer.len() - TAG_LEN);
        Ok(buffer)
    }
}

pub type Socks5Addr = crate::address::Socks5Addr;
