use std::{mem, ptr, slice};
use crate::SecureBit;

pub fn parse_salt(cipher_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if cipher_bytes.len() >= mem::size_of::<u64>() {
        let ptr = cipher_bytes.as_ptr() as *const u64;
        let value = unsafe { ptr::read_unaligned(ptr) };
        if value == 0x5f5f6465_746c6153u64 {
            let salt_bytes = unsafe { ptr::read_unaligned(ptr.add(1)) };
            let bytes = salt_bytes.to_ne_bytes();
            return (cipher_bytes[16..].to_vec(), Vec::from(bytes));
        }
    }
    (cipher_bytes.to_vec(), Vec::new())
}

pub fn add_salt(cipher_bytes: &[u8], salt: &[u8]) -> Vec<u8> {
    return if salt.len() > 0 {
        let mut result = Vec::with_capacity(cipher_bytes.len() + salt.len() + mem::size_of::<u64>());
        let sign = 0x5f5f6465_746c6153u64;
        result.extend_from_slice(sign.to_ne_bytes().as_slice());
        result.extend_from_slice(salt);
        result.extend_from_slice(cipher_bytes);
        result
    } else {
        cipher_bytes.to_vec()
    }
}

pub fn secure_bit_to_number(bit: SecureBit) -> usize {
    match bit {
        SecureBit::Bit64 => 64,
        SecureBit::Bit128 => 128,
        SecureBit::Bit192 => 192,
        SecureBit::Bit256 => 256,
    }
}