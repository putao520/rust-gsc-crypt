/// This macro provides a convenient way to create a `GscCrypt<bits>` instance or a `GscCrypt` instance.
#[macro_export]
macro_rules! new_crypt {
    (wrapper $key:expr) => {
        $crate::GscCrypt::new($key, $crate::SecureBit::Bit256, None::<String>)
    };
    (wrapper $key:expr,64) => {
        $crate::GscCrypt::new($key, $crate::SecureBit::Bit64, None::<String>)
    };
    (wrapper $key:expr,128) => {
        $crate::GscCrypt::new($key, $crate::SecureBit::Bit128, None::<String>)
    };
    (wrapper $key:expr,192) => {
        $crate::GscCrypt::new($key, $crate::SecureBit::Bit192, None::<String>)
    };
    (wrapper $key:expr,256) => {
        $crate::GscCrypt::new($key, $crate::SecureBit::Bit256, None::<String>)
    };
    (wrapper $key:expr,64, $iv:expr) => {
        $crate::GscCrypt::new($key, $crate::SecureBit::Bit64, Some($iv))
    };
    (wrapper $key:expr,128, $iv:expr) => {
        $crate::GscCrypt::new($key, $crate::SecureBit::Bit128, Some($iv))
    };
    (wrapper $key:expr,192, $iv:expr) => {
        $crate::GscCrypt::new($key, $crate::SecureBit::Bit192, Some($iv))
    };
    (wrapper $key:expr,256, $iv:expr) => {
        $crate::GscCrypt::new($key, $crate::SecureBit::Bit256, Some($iv))
    };
    ($key:expr) => {{
        use $crate::GscCryptTrait;

        $crate::GscCrypt256::new($key, None::<String>)
    }};
    ($key:expr,64) => {{
        use $crate::GscCryptTrait;

        $crate::GscCrypt64::new($key, None::<String>)
    }};
    ($key:expr,128) => {{
        use $crate::GscCryptTrait;

        $crate::GscCrypt128::new($key, None::<String>)
    }};
    ($key:expr,192) => {{
        use $crate::GscCryptTrait;

        $crate::GscCrypt192::new($key, None::<String>)
    }};
    ($key:expr,256) => {{
        use $crate::GscCryptTrait;

        $crate::GscCrypt256::new($key, None::<String>)
    }};
    ($key:expr,64, $iv:expr) => {{
        use $crate::GscCryptTrait;

        $crate::GscCrypt64::new($key, Some($iv))
    }};
    ($key:expr,128, $iv:expr) => {{
        use $crate::GscCryptTrait;

        $crate::GscCrypt128::new($key, Some($iv))
    }};
    ($key:expr,192, $iv:expr) => {{
        use $crate::GscCryptTrait;

        $crate::GscCrypt192::new($key, Some($iv))
    }};
    ($key:expr,256, $iv:expr) => {{
        use $crate::GscCryptTrait;

        $crate::GscCrypt256::new($key, Some($iv))
    }};
}

#[macro_export]
macro_rules! new_passphrase_crypt {
    ($passphrase:expr) => {
        $crate::GscCrypt::new_with_passphrase($passphrase, $crate::SecureBit::Bit256, None::<Vec<u8>>)
    };
    ($passphrase:expr,64) => {
        $crate::GscCrypt::new_with_passphrase($passphrase, $crate::SecureBit::Bit64, None::<Vec<u8>>)
    };
    ($passphrase:expr,128) => {
        $crate::GscCrypt::new_with_passphrase($passphrase, $crate::SecureBit::Bit128, None::<Vec<u8>>)
    };
    ($passphrase:expr,192) => {
        $crate::GscCrypt::new_with_passphrase($passphrase, $crate::SecureBit::Bit192, None::<Vec<u8>>)
    };
    ($passphrase:expr,256) => {
        $crate::GscCrypt::new_with_passphrase($passphrase, $crate::SecureBit::Bit256, None::<Vec<u8>>)
    };
    ($passphrase:expr,64, $salt:expr) => {
        $crate::GscCrypt::new_with_passphrase($passphrase, $crate::SecureBit::Bit64, Some($salt))
    };
    ($passphrase:expr,128, $salt:expr) => {
        $crate::GscCrypt::new_with_passphrase($passphrase, $crate::SecureBit::Bit128, Some($salt))
    };
    ($passphrase:expr,192, $salt:expr) => {
        $crate::GscCrypt::new_with_passphrase($passphrase, $crate::SecureBit::Bit192, Some($salt))
    };
    ($passphrase:expr,256, $salt:expr) => {
        $crate::GscCrypt::new_with_passphrase($passphrase, $crate::SecureBit::Bit256, Some($salt))
    };
}

#[macro_export]
macro_rules! crypt_from_cipher {
    ($passphrase:expr, $cipher_base64:expr) => {
        $crate::GscCrypt::from_cipher($passphrase, $crate::SecureBit::Bit256, $cipher_base64)
    };
    ($passphrase:expr,64, $cipher_base64:expr) => {
        $crate::GscCrypt::from_cipher($passphrase, $crate::SecureBit::Bit64, $cipher_base64)
    };
    ($passphrase:expr,128, $cipher_base64:expr) => {
        $crate::GscCrypt::from_cipher($passphrase, $crate::SecureBit::Bit128, $cipher_base64)
    };
    ($passphrase:expr,192, $cipher_base64:expr) => {
        $crate::GscCrypt::from_cipher($passphrase, $crate::SecureBit::Bit192, $cipher_base64)
    };
    ($passphrase:expr,256, $cipher_base64:expr) => {
        $crate::GscCrypt::from_cipher($passphrase, $crate::SecureBit::Bit256, $cipher_base64)
    };
}