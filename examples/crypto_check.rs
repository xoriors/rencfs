use std::{fs, io};
use std::env::args;
use std::fs::File;
use std::io::{Seek, Write};
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use secrecy::{SecretString, SecretVec};

use rencfs::crypto;
use rencfs::crypto::Cipher;
use rencfs::crypto::writer::CryptoWriter;

#[tokio::main]
async fn main() -> Result<()> {
    let cipher = Cipher::ChaCha20Poly1305;
    let key = Arc::new(get_key(cipher)?);

    let mut args = args();
    let _ = args.next(); // skip the program name
    let path_in = args.next().expect("path_in is missing");
    let path_out = format!(
        "/tmp/{}.enc",
        Path::new(&path_in).file_name().unwrap().to_str().unwrap()
    );
    let out = Path::new(&path_out).to_path_buf();
    if out.exists() {
        fs::remove_file(&out)?;
    }

    // copy
    let mut file_in = File::open(path_in)?;
    let file_out = File::create(path_out.clone())?;
    let mut writer = crypto::create_writer(file_out, cipher, key.clone());
    io::copy(&mut file_in, &mut writer)?;
    writer.flush()?;
    writer.finish()?;

    // check hash
    let mut reader = crypto::create_reader(File::open(path_out).unwrap(), cipher, key.clone());
    file_in.seek(io::SeekFrom::Start(0))?;
    let hash1 = crypto::hash_reader(&mut file_in)?;
    let hash2 = crypto::hash_reader(&mut reader)?;
    assert_eq!(hash1, hash2);

    Ok(())
}

fn get_key(cipher: Cipher) -> io::Result<SecretVec<u8>> {
    let password = SecretString::new("pass42".to_string());
    let salt: Vec<u8> = bincode::deserialize_from(File::open("/home/gnome/rencfs_data/security/key.salt")?).unwrap();

    // get key from location, useful to debug in existing data dir
    let derived_key = crypto::derive_key(&password, cipher, &salt).unwrap();
    let reader = crypto::create_reader(
        File::open("/home/gnome/rencfs_data/security/key.enc").unwrap(),
        cipher,
        Arc::new(derived_key),
    );
    let key: Vec<u8> = bincode::deserialize_from(reader).unwrap();
    Ok(SecretVec::new(key))
}
