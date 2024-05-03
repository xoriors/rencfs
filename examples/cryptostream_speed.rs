extern crate core;

use std::fs::OpenOptions;
use std::io;
use std::io::{Read, Write};
use std::path::Path;

use base64::decode;
use cryptostream::write;
use openssl::symm::Cipher;

fn main() -> io::Result<()> {
    let key: Vec<_> = "a".repeat(32).as_bytes().to_vec();
    let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();

    let mut input = OpenOptions::new().read(true).open("/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4").unwrap();
    let out_path = Path::new("./encrypted.enc");
    let out = OpenOptions::new().create(true).write(true).truncate(true).open(out_path)?;

    let mut encryptor = write::Encryptor::new(out, Cipher::chacha20(), &key, &iv).unwrap();

    let start = std::time::Instant::now();
    io::copy(&mut input, &mut encryptor).unwrap();
    let end = std::time::Instant::now();
    let duration = end.duration_since(start);
    let file_size = input.metadata()?.len();
    println!("speed MB/s {}", (file_size as f64 / duration.as_secs_f64()) / 1024.0 / 1024.0);

    Ok(())
}