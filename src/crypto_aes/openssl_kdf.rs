use crate::crypto_aes::cipher_params::CipherParams;
use crate::crypto_aes::evp_kdf::EvpKDF;

pub struct OpenSSLKDF {
}

impl OpenSSLKDF {
    pub fn execute(password: &str, key_size: usize, iv_size: usize, salt: Option<Vec<u8>>) -> CipherParams {
        let s = salt.unwrap_or_else(|| {
            let mut s = Vec::new();
            for _ in 0..8 {
                s.push(rand::random::<u8>());
            }
            s
        });
        let key = EvpKDF::new(key_size + iv_size, 1).compute(password.as_bytes(), s.as_slice());
        let iv = key[key_size..].to_vec();
        let key = key[..key_size].to_vec();
        return CipherParams {
            key,
            iv,
            salt: s
        };
    }
}