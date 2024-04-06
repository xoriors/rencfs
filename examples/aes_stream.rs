use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};
use aesstream::{AesReader, AesWriter};

use crypto::aessafe::{AesSafe256Decryptor, AesSafe256Encryptor};

fn main() {
    let key: [u8; 32] = "a".repeat(32).as_bytes().try_into().unwrap();
    // OsRng::default().fill_bytes(&mut key);

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("../../encrypted.enc").unwrap();
    let encryptor = AesSafe256Encryptor::new(&key);
    let mut writer = AesWriter::new(file, encryptor).unwrap();
    writer.write_all("012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789".as_bytes()).unwrap();
    writer.flush().unwrap();

    let file = OpenOptions::new()
        .read(true)
        .open("../../encrypted.enc").unwrap();
    let decryptor = AesSafe256Decryptor::new(&key);
    let mut reader = AesReader::new(file, decryptor).unwrap();
    let mut decrypted = String::new();
    let mut buf: [u8; 1] = [0; 1];
    reader.seek(std::io::SeekFrom::Start(105)).unwrap();
    reader.read_exact(&mut buf).unwrap();
    println!("{:?}", String::from_utf8_lossy(&buf));
    // reader.read_to_string(&mut decrypted).unwrap();
    // assert_eq!(decrypted, "Hello World!");
}