#[cfg(feature = "std")]
use std::intrinsics::copy;
#[cfg(feature = "std")]
use std::io::{ErrorKind, Read, Write};
#[cfg(feature = "std")]
use std::ops::Add;

use aes::{
    Aes128,
    cipher::{Block, BlockCipherKey},
};
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
#[cfg(feature = "std")]
use block_modes::block_padding::Padding;
#[cfg(feature = "std")]
use block_modes::BlockModeError;

use crate::{functions::*, generic_array::GenericArray, GscCryptError, GscCryptTrait};
#[cfg(feature = "std")]
use crate::generic_array::ArrayLength;
#[cfg(feature = "std")]
use crate::generic_array::typenum::{Add1, B1, IsGreaterOrEqual, PartialDiv, True, U16};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

#[cfg(feature = "std")]
const BLOCK_SIZE: usize = 16;

/// This struct can help you encrypt or decrypt data via AES-128 in a quick way.
#[derive(Debug, Clone)]
pub struct GscCrypt128 {
    key: BlockCipherKey<Aes128>,
    iv:  Block<Aes128>,
}

impl GscCryptTrait for GscCrypt128 {
    fn new<S: AsRef<[u8]>, V: AsRef<[u8]>>(key: S, iv: Option<V>) -> GscCrypt128 {
        let iv = match iv {
            Some(s) => {
                let mut iv = GenericArray::default();
                iv.copy_from_slice(s.as_ref());
                iv
            },
            None => GenericArray::default(),
        };

        let mut generic_key = GenericArray::default();
        generic_key.copy_from_slice(key.as_ref());

        GscCrypt128 {
            key: generic_key,
            iv
        }
    }

    fn encrypt_to_bytes<T: ?Sized + AsRef<[u8]>>(&self, data: &T) -> Vec<u8> {
        let data = data.as_ref();

        let data_length = data.len();

        let final_length = get_aes_cipher_len(data_length);

        let mut final_result = data.to_vec();

        final_result.reserve_exact(final_length - data_length);

        unsafe {
            final_result.set_len(final_length);
        }

        let cipher = Aes128Cbc::new_fix(&self.key, &self.iv);

        cipher.encrypt(&mut final_result, data_length).unwrap();

        final_result
    }

    #[cfg(feature = "std")]
    fn encrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, GscCryptError> {
        let mut data = Vec::new();

        reader.read_to_end(&mut data)?;

        let data_length = data.len();

        let final_length = get_aes_cipher_len(data_length);

        let mut final_result = data.to_vec();

        final_result.reserve_exact(final_length - data_length);

        unsafe {
            final_result.set_len(final_length);
        }

        let cipher = Aes128Cbc::new_fix(&self.key, &self.iv);

        cipher.encrypt(&mut final_result, data_length).unwrap();

        Ok(final_result)
    }

    #[cfg(feature = "std")]
    fn encrypt_reader_to_writer2<
        N: ArrayLength<u8> + PartialDiv<U16> + IsGreaterOrEqual<U16, Output = True>,
    >(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), GscCryptError> {
        let mut cipher = Aes128Cbc::new_fix(&self.key, &self.iv);

        let mut buffer: GenericArray<u8, N> = GenericArray::default();

        let mut l = 0;

        loop {
            match reader.read(&mut buffer[l..]) {
                Ok(c) => {
                    if c == 0 {
                        break;
                    }

                    l += c;

                    if l < BLOCK_SIZE {
                        continue;
                    }

                    let r = l % BLOCK_SIZE;
                    let e = l - r;

                    cipher.encrypt_blocks(to_blocks(&mut buffer[..e]));

                    writer.write_all(&buffer[..e])?;

                    unsafe {
                        copy(buffer.as_ptr().add(e), buffer.as_mut_ptr(), r);
                    }

                    l = r;
                },
                Err(ref err) if err.kind() == ErrorKind::Interrupted => {},
                Err(err) => return Err(GscCryptError::IOError(err)),
            }
        }

        cipher.encrypt_blocks(to_blocks(Pkcs7::pad(&mut buffer, l, BLOCK_SIZE).unwrap()));

        writer.write_all(&buffer[..get_aes_cipher_len(l)])?;

        Ok(writer.flush()?)
    }

    fn decrypt_bytes_to_bytes<T: ?Sized + AsRef<[u8]>>(
        &self,
        bytes: &T,
    ) -> Result<Vec<u8>, GscCryptError> {
        let bytes = bytes.as_ref();

        let mut final_result = bytes.to_vec();

        let cipher = Aes128Cbc::new_fix(&self.key, &self.iv);

        let length = cipher.decrypt(&mut final_result)?.len();

        unsafe {
            final_result.set_len(length);
        }

        Ok(final_result)
    }

    #[cfg(feature = "std")]
    fn decrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, GscCryptError> {
        let mut bytes = Vec::new();

        reader.read_to_end(&mut bytes)?;

        let mut final_result = bytes.to_vec();

        let cipher = Aes128Cbc::new_fix(&self.key, &self.iv);

        let length = cipher.decrypt(&mut final_result)?.len();

        unsafe {
            final_result.set_len(length);
        }

        Ok(final_result)
    }

    #[cfg(feature = "std")]
    #[allow(clippy::many_single_char_names)]
    fn decrypt_reader_to_writer2<
        N: ArrayLength<u8> + PartialDiv<U16> + IsGreaterOrEqual<U16, Output = True> + Add<B1>,
    >(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), GscCryptError>
    where
        <N as Add<B1>>::Output: ArrayLength<u8>, {
        let mut cipher = Aes128Cbc::new_fix(&self.key, &self.iv);

        let mut buffer: GenericArray<u8, Add1<N>> = GenericArray::default();

        let mut l = 0;

        loop {
            match reader.read(&mut buffer[l..N::USIZE]) {
                Ok(c) => {
                    l += c;

                    if c > 0 && l < BLOCK_SIZE {
                        continue;
                    }

                    let r = l % BLOCK_SIZE;
                    let e = if r > 0 { l + BLOCK_SIZE - r } else { l };

                    reader.read_exact(&mut buffer[l..e])?;

                    match reader.read_exact(&mut buffer[e..(e + 1)]) {
                        Ok(()) => {
                            cipher.decrypt_blocks(to_blocks(&mut buffer[..e]));

                            writer.write_all(&buffer[..e])?;

                            buffer[0] = buffer[e];

                            l = 1;
                        },
                        Err(ref err) if err.kind() == ErrorKind::UnexpectedEof => {
                            cipher.decrypt_blocks(to_blocks(&mut buffer[..e]));

                            writer
                                .write_all(Pkcs7::unpad(&buffer[..e]).map_err(|_| {
                                    GscCryptError::DecryptError(BlockModeError)
                                })?)?;

                            break;
                        },
                        Err(err) => return Err(GscCryptError::IOError(err)),
                    }
                },
                Err(ref err) if err.kind() == ErrorKind::Interrupted => {},
                Err(err) => return Err(GscCryptError::IOError(err)),
            }
        }

        Ok(writer.flush()?)
    }
}
