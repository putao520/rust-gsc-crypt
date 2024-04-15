/*!
# GscCrypt

GscCrypt is a Java/PHP/NodeJS/Rust library to encrypt/decrpyt strings, files, or data, using Data Encryption Standard(DES) or Advanced Encryption Standard(AES) algorithms. It supports CBC block cipher mode, PKCS5 padding and 64, 128, 192 or 256-bits key length.

## For Rust

### Example

```rust
use gsc_crypt::{new_crypt, GscCryptTrait};

let mc = new_crypt!("gsckey", 256);

let base64 = mc.encrypt_str_to_base64("http://gsclen.org");

assert_eq!("DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ=", base64);

assert_eq!("http://gsclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
```

## Change the Buffer Size

The default buffer size for the `encrypt_reader_to_writer` method and the `decrypt_reader_to_writer` method is 4096 bytes. If you want to change that, you can use the `encrypt_reader_to_writer2` method or the `decrypt_reader_to_writer2` method, and define a length explicitly.

For example, to change the buffer size to 256 bytes,

```rust
use std::io::Cursor;

use base64::Engine;
use gsc_crypt::{new_crypt, GscCryptTrait};
use gsc_crypt::generic_array::typenum::U256;

let mc = new_crypt!("gsckey", 256);

# #[cfg(feature = "std")] {
let mut reader = Cursor::new("http://gsclen.org");
let mut writer = Vec::new();

mc.encrypt_reader_to_writer2::<U256>(&mut reader, &mut writer).unwrap();

let base64 = base64::engine::general_purpose::STANDARD.encode(&writer);

assert_eq!("DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ=", base64);

assert_eq!("http://gsclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
# }
```

## No Std

Disable the default features to compile this crate without std.

```toml
[dependencies.gsc-crypt]
version = "*"
default-features = false
```

## For Java

Refer to https://github.com/gsclen/GscCrypt.

## For PHP

Refer to https://github.com/gsclen/GscCrypt.

## For NodeJS

Refer to https://github.com/gsclen/node-gsccrypt
*/

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod ciphers;
mod errors;
mod functions;
mod macros;
mod secure_bit;
mod traits;
mod crypto_aes;

#[cfg(feature = "std")]
use std::io::{Read, Write};
#[cfg(feature = "std")]
use std::ops::Add;
use base64::Engine;

pub use ciphers::{
    aes128::GscCrypt128, aes192::GscCrypt192, aes256::GscCrypt256, des64::GscCrypt64,
};
pub use digest::generic_array;
pub use errors::GscCryptError;
#[cfg(feature = "std")]
use generic_array::typenum::{IsGreaterOrEqual, PartialDiv, True, B1, U16};
#[cfg(feature = "std")]
use generic_array::ArrayLength;
pub use secure_bit::SecureBit;
pub use traits::GscCryptTrait;
use crate::crypto_aes::cipher_params::CipherParams;
use crate::crypto_aes::openssl_kdf::OpenSSLKDF;
use crate::crypto_aes::salt::{add_salt, parse_salt, secure_bit_to_number};

#[derive(Debug, Clone)]
enum GscCryptCipher {
    DES64(GscCrypt64),
    AES128(GscCrypt128),
    AES192(GscCrypt192),
    AES256(GscCrypt256),
}

/// This struct can help you encrypt or decrypt data in a quick way.
#[derive(Debug, Clone)]
pub struct GscCrypt {
    cipher: GscCryptCipher,
    salt: Vec<u8>,
    passphrase: Option<String>,
    bit: SecureBit,
}

impl GscCrypt {
    /// Create a new `GscCrypt` instance. You may want to use the `new_gsc_crypt!` macro.
    pub fn new<S: AsRef<[u8]>, V: AsRef<[u8]>>(
        key: S,
        bit: SecureBit,
        iv: Option<V>,
    ) -> GscCrypt {
        let cipher = match bit {
            SecureBit::Bit64 => GscCryptCipher::DES64(GscCrypt64::new(key, iv)),
            SecureBit::Bit128 => GscCryptCipher::AES128(GscCrypt128::new(key, iv)),
            SecureBit::Bit192 => GscCryptCipher::AES192(GscCrypt192::new(key, iv)),
            SecureBit::Bit256 => GscCryptCipher::AES256(GscCrypt256::new(key, iv)),
        };

        GscCrypt {
            cipher,
            salt: Vec::new(),
            passphrase: None,
            bit,
        }
    }

    pub fn new_with_passphrase(
        passphrase: &str,
        bit: SecureBit,
        salt: Option<Vec<u8>>
    ) -> GscCrypt {
        let key_size = secure_bit_to_number(bit)/8;
        let derived_params = get_derived_params(passphrase, key_size, salt);

        let cipher = match bit {
            SecureBit::Bit64 => GscCryptCipher::DES64(GscCrypt64::new(derived_params.key, Some(derived_params.iv))),
            SecureBit::Bit128 => GscCryptCipher::AES128(GscCrypt128::new(derived_params.key, Some(derived_params.iv))),
            SecureBit::Bit192 => GscCryptCipher::AES192(GscCrypt192::new(derived_params.key, Some(derived_params.iv))),
            SecureBit::Bit256 => GscCryptCipher::AES256(GscCrypt256::new(derived_params.key, Some(derived_params.iv))),
        };
        GscCrypt {
            cipher,
            salt: derived_params.salt,
            passphrase: Some(passphrase.to_string()),
            bit,
        }
    }

    // 输出 base64 字符串
    pub fn signature(&mut self, cipher_bytes: Vec<u8>) -> String {
        base64::engine::general_purpose::STANDARD.encode(
            add_salt(cipher_bytes.as_slice(), self.salt.as_slice())
        )
    }

    // cipher_base64: 输入的密文 base64 字符串
    pub fn verify_cipher(&self, cipher_base64: &str) -> Result<(GscCrypt, Vec<u8>), GscCryptError> {
        let passphrase = self.passphrase.clone().unwrap();
        Self::from_cipher(passphrase.as_str(), self.bit, cipher_base64)
    }

    pub fn from_cipher(passphrase: &str, bit: SecureBit, cipher_base64: &str) -> Result<(GscCrypt, Vec<u8>), GscCryptError> {
        // base64 转数据 vec[u8]
        let cipher_bytes = base64::engine::general_purpose::STANDARD.decode(cipher_base64.as_bytes())?;
        let (data, salt) = parse_salt(cipher_bytes.as_slice());
        Ok((Self::new_with_passphrase(passphrase, bit, Some(salt)), data))
    }
}

fn get_derived_params(passphrase: &str, key_size: usize, salt: Option<Vec<u8>>) -> CipherParams {
    // let bit_num = secure_bit_to_number(bit);
    // let key_size = bit_num/8;
    let iv_size = if key_size == 8 { 8 } else { 16 };
    OpenSSLKDF::execute(passphrase, key_size, iv_size, salt)
}

impl GscCryptTrait for GscCrypt {
    #[inline]
    fn new<S: AsRef<[u8]>, V: AsRef<[u8]>>(key: S, iv: Option<V>) -> GscCrypt {
        GscCrypt::new(key, SecureBit::default(), iv)
    }

    #[inline]
    fn encrypt_to_bytes<T: ?Sized + AsRef<[u8]>>(&self, data: &T) -> Vec<u8> {
        match &self.cipher {
            GscCryptCipher::DES64(mc) => mc.encrypt_to_bytes(data),
            GscCryptCipher::AES128(mc) => mc.encrypt_to_bytes(data),
            GscCryptCipher::AES192(mc) => mc.encrypt_to_bytes(data),
            GscCryptCipher::AES256(mc) => mc.encrypt_to_bytes(data),
        }
    }

    #[cfg(feature = "std")]
    #[inline]
    fn encrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, GscCryptError> {
        match &self.cipher {
            GscCryptCipher::DES64(mc) => mc.encrypt_reader_to_bytes(reader),
            GscCryptCipher::AES128(mc) => mc.encrypt_reader_to_bytes(reader),
            GscCryptCipher::AES192(mc) => mc.encrypt_reader_to_bytes(reader),
            GscCryptCipher::AES256(mc) => mc.encrypt_reader_to_bytes(reader),
        }
    }

    #[cfg(feature = "std")]
    #[inline]
    fn encrypt_reader_to_writer2<
        N: ArrayLength<u8> + PartialDiv<U16> + IsGreaterOrEqual<U16, Output = True>,
    >(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), GscCryptError> {
        match &self.cipher {
            GscCryptCipher::DES64(mc) => mc.encrypt_reader_to_writer2::<N>(reader, writer),
            GscCryptCipher::AES128(mc) => mc.encrypt_reader_to_writer2::<N>(reader, writer),
            GscCryptCipher::AES192(mc) => mc.encrypt_reader_to_writer2::<N>(reader, writer),
            GscCryptCipher::AES256(mc) => mc.encrypt_reader_to_writer2::<N>(reader, writer),
        }
    }

    #[inline]
    fn decrypt_bytes_to_bytes<T: ?Sized + AsRef<[u8]>>(
        &self,
        bytes: &T,
    ) -> Result<Vec<u8>, GscCryptError> {
        match &self.cipher {
            GscCryptCipher::DES64(mc) => mc.decrypt_bytes_to_bytes(bytes),
            GscCryptCipher::AES128(mc) => mc.decrypt_bytes_to_bytes(bytes),
            GscCryptCipher::AES192(mc) => mc.decrypt_bytes_to_bytes(bytes),
            GscCryptCipher::AES256(mc) => mc.decrypt_bytes_to_bytes(bytes),
        }
    }

    #[cfg(feature = "std")]
    #[inline]
    fn decrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, GscCryptError> {
        match &self.cipher {
            GscCryptCipher::DES64(mc) => mc.decrypt_reader_to_bytes(reader),
            GscCryptCipher::AES128(mc) => mc.decrypt_reader_to_bytes(reader),
            GscCryptCipher::AES192(mc) => mc.decrypt_reader_to_bytes(reader),
            GscCryptCipher::AES256(mc) => mc.decrypt_reader_to_bytes(reader),
        }
    }

    #[cfg(feature = "std")]
    #[inline]
    fn decrypt_reader_to_writer2<
        N: ArrayLength<u8> + PartialDiv<U16> + IsGreaterOrEqual<U16, Output = True> + Add<B1>,
    >(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), GscCryptError>
    where
        <N as Add<B1>>::Output: ArrayLength<u8>, {
        match &self.cipher {
            GscCryptCipher::DES64(mc) => mc.decrypt_reader_to_writer(reader, writer),
            GscCryptCipher::AES128(mc) => mc.decrypt_reader_to_writer(reader, writer),
            GscCryptCipher::AES192(mc) => mc.decrypt_reader_to_writer(reader, writer),
            GscCryptCipher::AES256(mc) => mc.decrypt_reader_to_writer(reader, writer),
        }
    }
}

