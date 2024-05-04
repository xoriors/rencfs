use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use argon2::password_hash::rand_core::RngCore;
use rand::thread_rng;
use ring::aead::{AES_256_GCM, CHACHA20_POLY1305};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::fs;

use rencfs::crypto;
use rencfs::crypto::Cipher;
use rencfs::crypto::writer::CryptoWriter;
use rencfs::encryptedfs::FsError;

fn main() {
    // let password = SecretString::new("password".to_string());
    // let salt = crypto::hash_secret(&password);
    // let cipher = Cipher::ChaCha20;
    // let key = crypto::derive_key(&password, &cipher, salt).unwrap();
    //
    // let cipher = Cipher::ChaCha20;
    //
    // let path = PathBuf::from("/tmp/test.txt");
    // let mut writer = crypto::create_crypto_writer(OpenOptions::new().read(true).write(true).create(true).open(path.clone()).unwrap(),
    //                                               &cipher, &key);
    // let x = "Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! Hello, world!".to_string();
    // bincode::serialize_into(&mut writer, &x).unwrap();
    // // writer.write_all(x.as_bytes()).unwrap();
    // writer.flush().unwrap();
    // writer.finish().unwrap();
    //
    // let mut reader = crypto::create_crypto_reader(File::open(path).unwrap(), &cipher, &key);
    // let mut buf = vec![0; x.len()];
    // // reader.read_exact(&mut buf).unwrap();
    // let dec: String = bincode::deserialize_from(&mut reader).unwrap();
    // // let dec = String::from_utf8(buf).unwrap();
    // println!("{}", dec);
    // assert_eq!(dec, x);

    // derive key from password
    let password = SecretString::new("password".to_string());
    let salt = crypto::hash_secret(&password);
    let cipher = Cipher::ChaCha20;
    let derived_key = crypto::derive_key(&password, &cipher, salt).unwrap();
    let path = PathBuf::from("/tmp/key.enc");
    let _ = fs::remove_file(&path);

    // first time, create a random key and encrypt it with the derived key from password

    let mut key: Vec<u8> = vec![];
    let key_len = match cipher {
        Cipher::ChaCha20 => CHACHA20_POLY1305.key_len(),
        Cipher::Aes256Gcm => AES_256_GCM.key_len(),
    };
    key.resize(key_len, 0);
    thread_rng().fill_bytes(&mut key);
    println!("key: {:?}", key);
    let key = SecretVec::new(key);
    let key_store = KeyStore::new(key);
    println!("hash {:?}", key_store.hash);
    let mut writer = crypto::create_writer(OpenOptions::new().read(true).write(true).create(true).open(path.clone()).unwrap(),
                                           &cipher, &derived_key, 42_u64);
    bincode::serialize_into(&mut writer, &key_store).unwrap();
    writer.flush().unwrap();
    writer.finish().unwrap();

    // read key

    let reader = crypto::create_reader(File::open(path).unwrap(), &cipher, &derived_key);
    let key_store: KeyStore = bincode::deserialize_from(reader).map_err(|_| FsError::InvalidPassword).unwrap();
    println!("key {:?}", key_store.key.expose_secret());
    println!("hash {:?}", key_store.hash);
    // check hash
    if key_store.hash != crypto::hash(key_store.key.expose_secret()) {
        eprintln!("Invalid password");
        return;
    }
}

fn key_serialize<S>(key: &SecretVec<u8>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    s.collect_seq(key.expose_secret())
}

fn key_unserialize<'de, D>(deserializer: D) -> Result<SecretVec<u8>, D::Error>
    where D: Deserializer<'de> {
    let vec = Vec::deserialize(deserializer)?;
    Ok(SecretVec::new(vec))
}

#[derive(Serialize, Deserialize)]
struct KeyStore {
    #[serde(serialize_with = "key_serialize")]
    #[serde(deserialize_with = "key_unserialize")]
    key: SecretVec<u8>,
    hash: [u8; 32],
}

impl KeyStore {
    fn new(key: SecretVec<u8>) -> Self {
        let hash = crypto::hash(key.expose_secret());
        Self { key, hash }
    }
}
