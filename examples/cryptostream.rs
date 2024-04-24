extern crate core;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use base64::decode;
use cryptostream::{read, write};
use openssl::symm::Cipher;

fn main() {
// This is the cipher text, base64-encoded to avoid any whitespace munging. In this
// contrived example, we are using a binary `Vec<u8>` as the `Read` source containing
// the encrypted data; in practice it could be a binary file, a network stream, or
// anything else.
    let src: Vec<u8> = decode(concat!(
    "vuU+0SXFWQLu8vl/o1WzmPCmf7x/O6ToGQ162Aq2CHxcnc/ax/Q8nTbRlNn0OSPrFuE3yDdO",
    "VC35RmwtUIlxKIkWbnxJpRF5yRJvVByQgWX1qLW8DfMjRp7gVaFNv4qr7G65M6hbSx6hGJXv",
    "Q6s1GiFwi91q0V17DI79yVrINHCXdBnUOqeLGfJ05Edu+39EQNYn4dky7VdgTP2VYZE7Vw==",
    ))
        .unwrap();
    let key: Vec<_> = decode("kjtbxCPw3XPFThb3mKmzfg==").unwrap();
    let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();

// The source can be anything implementing `Read`. In this case, a simple &[u8] slice.
    let mut decryptor =
        read::Decryptor::new(src.as_slice(), Cipher::aes_128_cbc(), &key, &iv).unwrap();

    let mut decrypted = [0_u8; 1024]; // a buffer to decrypt into
    let mut bytes_decrypted = 0;

    loop {
        // Just read from the `Decryptor` as if it were any other `Read` impl,
        // the decryption takes place automatically.
        let read_count = decryptor.read(&mut decrypted[bytes_decrypted..]).unwrap();
        bytes_decrypted += read_count;
        if read_count == 0 {
            break;
        }
    }

    // println!("{}", String::from_utf8_lossy(&decrypted));

    let key: Vec<_> = decode("kjtbxCPw3XPFThb3mKmzfg==").unwrap();
    let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .open("encrypted_file.enc")
        .unwrap();
    let mut encryptor =
        write::Encryptor::new(file, Cipher::aes_128_cbc(), &key, &iv).unwrap();
    encryptor.write_all(b"test-42").unwrap();
    encryptor.flush().unwrap();

    let file = File::open("encrypted_file.enc").unwrap();
    let mut decryptor =
        read::Decryptor::new(file, Cipher::aes_128_cbc(), &key, &iv).unwrap();

    let mut decrypted = [0_u8; 1024]; // a buffer to decrypt into
    let mut bytes_decrypted = 0;
    loop {
        // Just read from the `Decryptor` as if it were any other `Read` impl,
        // the decryption takes place automatically.
        let read_count = decryptor.read(&mut decrypted[bytes_decrypted..]).unwrap();
        bytes_decrypted += read_count;
        if read_count == 0 {
            break;
        }
    }

    println!("dec {}", String::from_utf8_lossy(&decrypted));
}