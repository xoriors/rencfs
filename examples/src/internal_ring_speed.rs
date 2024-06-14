#![deny(warnings)]
use std::env::args;
use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::{fs, io};

use ring::aead::Aad;
use ring::aead::BoundKey;
use ring::aead::Nonce;
use ring::aead::NonceSequence;
use ring::aead::OpeningKey;
use ring::aead::SealingKey;
use ring::aead::UnboundKey;
use ring::aead::CHACHA20_POLY1305;
use ring::aead::NONCE_LEN;
use ring::error::Unspecified;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;

struct CounterNonceSequence(u32);

impl NonceSequence for CounterNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];

        let bytes = self.0.to_be_bytes();
        nonce_bytes[8..].copy_from_slice(&bytes);

        self.0 += 1; // advance the counter
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

fn main() -> io::Result<()> {
    let mut args = args();
    let _ = args.next(); // skip the program name
    let in_path = args.next().expect("in_path is missing");
    println!("in_path = {}", in_path);
    let input = OpenOptions::new().read(true).open(in_path.clone()).unwrap();
    let out_path = format!(
        "/tmp/{}.enc",
        Path::new(&in_path).file_name().unwrap().to_str().unwrap()
    );
    let out = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(out_path.clone())?;

    // Create a new instance of SystemRandom to be used as the single source of entropy
    let rand = SystemRandom::new();

    // Generate a new symmetric encryption key
    let mut key_bytes = vec![0; CHACHA20_POLY1305.key_len()];
    rand.fill(&mut key_bytes).unwrap();

    // Create a new AEAD key without a designated role or nonce sequence
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap();

    // Create a new NonceSequence type which generates nonces
    let nonce_sequence = CounterNonceSequence(1);

    // Create a new AEAD key for encrypting and signing ("sealing"), bound to a nonce sequence
    // The SealingKey can be used multiple times, each time a new nonce will be used
    let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);

    // This data will be authenticated but not encrypted
    // let associated_data = Aad::empty(); // is optional so can be empty
    // let associated_data = Aad::from(b"additional public data");

    let file_size = input.metadata()?.len();

    let mut input = BufReader::new(input);
    let mut out = BufWriter::new(out);

    let start = std::time::Instant::now();
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let len = {
            let mut pos = 0;
            loop {
                match input.read(&mut buffer[pos..]) {
                    Ok(read) => {
                        pos += read;
                        if read == 0 {
                            break;
                        }
                    }
                    Err(err) => return Err(err),
                }
            }
            pos
        };
        if len == 0 {
            break;
        }
        if len != buffer.len() {
            println!("len = {}", len);
        }
        // Data to be encrypted
        let mut data = &mut buffer[..len];
        //         let mut data = buffer[..len].to_vec();

        // Create a mutable copy of the data that will be encrypted in place
        //         let mut in_out = data.clone();

        // Encrypt the data with AEAD using the AES_256_GCM algorithm
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut data)
            .unwrap();

        let _ = out.write(&data).unwrap();
        let _ = out.write(tag.as_ref()).unwrap();
    }
    out.flush().unwrap();
    let end = std::time::Instant::now();
    let duration = end.duration_since(start);
    println!("duration = {:?}", duration);
    println!(
        "speed MB/s {}",
        (file_size as f64 / duration.as_secs_f64()) / 1024.0 / 1024.0
    );

    // decrypt
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap();
    let nonce_sequence = CounterNonceSequence(1);
    let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);

    let input = OpenOptions::new().read(true).open(out_path).unwrap();
    let out_path = "/tmp/encrypted.dec";
    let out = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(Path::new(out_path))?;

    let start = std::time::Instant::now();
    let mut buffer = vec![0; 1024 * 1024 + CHACHA20_POLY1305.tag_len()];
    let mut input = BufReader::new(input);
    let mut out = BufWriter::new(out);
    loop {
        let len = {
            let mut pos = 0;
            loop {
                match input.read(&mut buffer[pos..]) {
                    Ok(read) => {
                        pos += read;
                        if read == 0 {
                            break;
                        }
                    }
                    Err(err) => return Err(err),
                }
            }
            pos
        };
        if len == 0 {
            break;
        }
        if len != buffer.len() {
            println!("len = {}", len);
        }
        // Data to be encrypted
        let mut ciphertext = &mut buffer[..len];

        // Create a mutable copy of the data that will be encrypted in place
        //         let mut in_out = data.clone();

        // Encrypt the data with AEAD using the AES_256_GCM algorithm
        let plaintext = opening_key
            .open_within(Aad::empty(), &mut ciphertext, 0..)
            .unwrap();
        // let dec = opening_key.open_in_place(Aad::empty(), &mut data).unwrap();

        let _ = out.write(&plaintext).unwrap();
    }
    out.flush().unwrap();
    let end = std::time::Instant::now();
    let duration = end.duration_since(start);
    println!("duration = {:?}", duration);
    println!(
        "speed MB/s {}",
        (file_size as f64 / duration.as_secs_f64()) / 1024.0 / 1024.0
    );

    fs::remove_file(out_path).unwrap();

    Ok(())
}
