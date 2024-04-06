use std::fs::OpenOptions;
use std::io;
use std::path::Path;
use std::time::Instant;

use aesstream::AesWriter;
use crypto::aessafe::AesSafe256Encryptor;

fn main() -> io::Result<()> {
    let mut input = OpenOptions::new().read(true).open("/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4").unwrap();
    let out_path = Path::new("./encrypted.enc");
    let out = OpenOptions::new().create(true).write(true).open(out_path.clone())?;
    let read_out = OpenOptions::new().read(true).open(out_path)?;

    let key: [u8; 32] = "a".repeat(32).as_bytes().try_into().unwrap();
    let encryptor = AesSafe256Encryptor::new(&key);
    let mut writer = AesWriter::new(out, encryptor)?;

    let start = Instant::now();
    io::copy(&mut input, &mut writer)?;
    let end = Instant::now();
    println!("Time elapsed: {:?}", end.duration_since(start));
    let file_size = input.metadata()?.len();
    println!("speed MB/s {}", (file_size as f64 / end.duration_since(start).as_secs_f64()) / 1024.0 / 1024.0);

    Ok(())
}