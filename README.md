GscCrypt
====================

[![CI](https://github.com/gsclen/rust-GscCrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/gsclen/rust-GscCrypt/actions/workflows/ci.yml)

GscCrypt is a Compatible with the default AES parameter mode in CryptoJS library to encrypt/decrpyt strings, files, or data, using Data Encryption Standard(DES) or Advanced Encryption Standard(AES) algorithms. It supports CBC block cipher mode, PKCS5 padding and 64, 128, 192 or 256-bits key length.

## For Rust

### Example

```rust
use gsc_crypt::{new_gsc_crypt, GscCryptTrait};

let mc = new_gsc_crypt!("gsckey", 256);

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
use gsc_crypt::{new_gsc_crypt, GscCryptTrait};
use gsc_crypt::generic_array::typenum::U256;

let mc = new_gsc_crypt!("gsckey", 256);

let mut reader = Cursor::new("http://gsclen.org");
let mut writer = Vec::new();

mc.encrypt_reader_to_writer2::<U256>(&mut reader, &mut writer).unwrap();

let base64 = base64::engine::general_purpose::STANDARD.encode(&writer);

assert_eq!("DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ=", base64);

assert_eq!("http://gsclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
```

## No Std

Disable the default features to compile this crate without std.

```toml
[dependencies.gsc-crypt]
version = "*"
default-features = false
```


## License

[Apache-2.0](LICENSE)

## What's More?

Please check out our web page at

