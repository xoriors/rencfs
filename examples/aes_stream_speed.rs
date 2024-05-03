use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use aesstream::{AesReader, AesWriter};
use rust_crypto::aessafe::{AesSafe256Decryptor, AesSafe256Encryptor};

fn main() -> io::Result<()> {
    let mut input = OpenOptions::new().read(true).open("/home/gnome/Downloads/bfg-1.14.0.jar").unwrap();
    let out_path = Path::new("/tmp/encrypted.enc");
    let out = OpenOptions::new().create(true).write(true).truncate(true).open(out_path.clone())?;

    let key: [u8; 32] = "a".repeat(32).as_bytes().try_into().unwrap();
    let encryptor = AesSafe256Encryptor::new(&key);
    let mut writer = AesWriter::new(out, encryptor)?;

    let start = Instant::now();
    io::copy(&mut input, &mut writer)?;
    let end = Instant::now();
    println!("Time elapsed: {:?}", end.duration_since(start));
    let file_size = input.metadata()?.len();
    println!("speed MB/s {}", (file_size as f64 / end.duration_since(start).as_secs_f64()) / 1024.0 / 1024.0);

    let input = OpenOptions::new().read(true).open(out_path).unwrap();
    let out_path = Path::new("/tmp/encrypted.dec");
    let mut out = OpenOptions::new().create(true).write(true).truncate(true).open(out_path.clone())?;
    let decryptor = AesSafe256Decryptor::new(&key);
    let mut reader = AesReader::new(input, decryptor)?;
    let start = Instant::now();
    io::copy(&mut reader, &mut out)?;
    let end = Instant::now();
    println!("Time elapsed: {:?}", end.duration_since(start));
    let file_size = out_path.metadata()?.len();
    println!("speed MB/s {}", (file_size as f64 / end.duration_since(start).as_secs_f64()) / 1024.0 / 1024.0);

    Ok(())
}