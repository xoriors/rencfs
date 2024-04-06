use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use ring::error::Unspecified;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use ring::aead::Algorithm;
use ring::aead::AES_128_GCM;
use ring::aead::AES_256_GCM;
use ring::aead::CHACHA20_POLY1305;
use ring::aead::UnboundKey;
use ring::aead::BoundKey;
use ring::aead::SealingKey;
use ring::aead::OpeningKey;
use ring::aead::Aad;
use ring::aead::Tag;
use ring::aead::NonceSequence;
use ring::aead::NONCE_LEN;
use ring::aead::Nonce;
use ring::aead::quic::CHACHA20;

struct CounterNonceSequence(u32);

impl NonceSequence for CounterNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];

        let bytes = self.0.to_be_bytes();
        nonce_bytes[8..].copy_from_slice(&bytes);
        println!("nonce_bytes = {}", hex::encode(&nonce_bytes));

        self.0 += 1; // advance the counter
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

fn main() -> std::io::Result<()> {
    let mut input = OpenOptions::new().read(true).open("/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4").unwrap();
    let out_path = Path::new("./encrypted.enc");
    let mut out = OpenOptions::new().create(true).write(true).open(out_path)?;

    // Create a new instance of SystemRandom to be used as the single source of entropy
    let rand = SystemRandom::new();

// Generate a new symmetric encryption key
    let mut key_bytes = vec![0; CHACHA20_POLY1305.key_len()];
    rand.fill(&mut key_bytes).unwrap();
    println!("key_bytes = {}", hex::encode(&key_bytes)); // don't print this in production code

// Create a new AEAD key without a designated role or nonce sequence
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap();

    // Create a new NonceSequence type which generates nonces
    let nonce_sequence = CounterNonceSequence(1);

// Create a new AEAD key for encrypting and signing ("sealing"), bound to a nonce sequence
// The SealingKey can be used multiple times, each time a new nonce will be used
    let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);

    // This data will be authenticated but not encrypted
//let associated_data = Aad::empty(); // is optional so can be empty
    let associated_data = Aad::from(b"additional public data");

    let start = std::time::Instant::now();
    let mut buffer = [0; 4096];
    loop {
        let len = input.read(&mut buffer).unwrap();
        if len == 0 {
            break;
        }
// Data to be encrypted
        let data = buffer[..len].to_vec();

// Create a mutable copy of the data that will be encrypted in place
        let mut in_out = data.clone();

// Encrypt the data with AEAD using the AES_256_GCM algorithm
        let tag = sealing_key.seal_in_place_separate_tag(associated_data, &mut in_out).unwrap();

        out.write(&in_out).unwrap();
    }
    out.flush().unwrap();
    let end = std::time::Instant::now();
    let duration = end.duration_since(start);
    let file_size = input.metadata()?.len();
    println!("duration = {:?}", duration);
    println!("speed MB/s {}", (file_size as f64 / duration.as_secs_f64()) / 1024.0 / 1024.0);

    Ok(())
}