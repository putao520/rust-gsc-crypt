use alloc::string::FromUtf8Error;
use core::fmt::{self, Display, Formatter};
#[cfg(feature = "std")]
use std::error::Error;
#[cfg(feature = "std")]
use std::io::Error as IOError;

use base64::DecodeError;
use block_modes::BlockModeError;

/// Errors for GscCrypt.
#[derive(Debug)]
pub enum GscCryptError {
    #[cfg(feature = "std")]
    IOError(IOError),
    Base64Error(DecodeError),
    StringError(FromUtf8Error),
    DecryptError(BlockModeError),
}

#[cfg(feature = "std")]
impl From<IOError> for GscCryptError {
    #[inline]
    fn from(error: IOError) -> GscCryptError {
        GscCryptError::IOError(error)
    }
}

impl From<DecodeError> for GscCryptError {
    #[inline]
    fn from(error: DecodeError) -> GscCryptError {
        GscCryptError::Base64Error(error)
    }
}

impl From<FromUtf8Error> for GscCryptError {
    #[inline]
    fn from(error: FromUtf8Error) -> GscCryptError {
        GscCryptError::StringError(error)
    }
}

impl From<BlockModeError> for GscCryptError {
    #[inline]
    fn from(error: BlockModeError) -> GscCryptError {
        GscCryptError::DecryptError(error)
    }
}

impl Display for GscCryptError {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match self {
            #[cfg(feature = "std")]
            GscCryptError::IOError(err) => Display::fmt(err, f),
            GscCryptError::Base64Error(err) => Display::fmt(err, f),
            GscCryptError::StringError(err) => Display::fmt(err, f),
            GscCryptError::DecryptError(err) => Display::fmt(err, f),
        }
    }
}

#[cfg(feature = "std")]
impl Error for GscCryptError {}
