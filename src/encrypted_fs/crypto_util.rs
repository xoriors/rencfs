use std::fs::File;
use cryptostream::{read, write};
use openssl::symm::Cipher;
use std::os::unix::fs::MetadataExt;
use rand::Rng;
use std::io::{Read, Write};
use base64::decode;
use std::io;
use crate::encrypted_fs::EncryptionType;

pub fn create_encryptor(mut file: File, encryption_type: &EncryptionType, key: &Vec<u8>) -> write::Encryptor<File> {
    let mut iv: Vec<u8> = vec![0; 16];
    if file.metadata().unwrap().size() == 0 {
        // generate random IV
        rand::thread_rng().fill_bytes(&mut iv);
        file.write_all(&iv).unwrap();
    } else {
        // read IV from file
        file.read_exact(&mut iv).unwrap();
    }
    write::Encryptor::new(file, Cipher::chacha20(), &key, &iv).unwrap()
}

pub fn create_decryptor(mut file: File, encryption_type: &EncryptionType, key: &Vec<u8>) -> read::Decryptor<File> {
    let mut iv: Vec<u8> = vec![0; 16];
    if file.metadata().unwrap().size() == 0 {
        // generate random IV
        rand::thread_rng().fill_bytes(&mut iv);
        file.write_all(&iv).unwrap();
    } else {
        // read IV from file
        file.read_exact(&mut iv).unwrap();
    }
    read::Decryptor::new(file, Cipher::chacha20(), &key, &iv).unwrap()
}

pub fn encrypt_string(s: &str, encryption_type: &EncryptionType, key: &Vec<u8>) -> String {
    // use the same IV so the same string will be encrypted to the same value
    let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();

    let mut cursor = io::Cursor::new(vec![]);

    let mut encryptor = write::Encryptor::new(cursor, Cipher::chacha20(), &key, &iv).unwrap();
    encryptor.write_all(s.as_bytes()).unwrap();
    cursor = encryptor.finish().unwrap();
    base64::encode(&cursor.into_inner())
}

pub fn decrypt_string(s: &str, encryption_type: &EncryptionType, key: &Vec<u8>) -> String {
    // use the same IV so the same string will be encrypted to the same value
    let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();

    let vec = decode(s).unwrap();
    let cursor = io::Cursor::new(vec);

    let mut decryptor = read::Decryptor::new(cursor, Cipher::chacha20(), &key, &iv).unwrap();
    let mut decrypted = String::new();
    decryptor.read_to_string(&mut decrypted).unwrap();
    decrypted
}

pub fn decrypt_and_unnormalize_end_file_name(name: &str, encryption_type: &EncryptionType, key: &Vec<u8>) -> String {
    let mut name = String::from(name);
    if name != "$." && name != "$.." {
        name = name.replace("|", "/");
        name = decrypt_string(&name, encryption_type, key);
    }
    name.to_string()
}

pub fn derive_key(password: &str, encryption_type: &EncryptionType, rounds: u32, salt: &str) -> Vec<u8> {
    let mut dk = vec![];
    let key_len =match encryption_type {
        EncryptionType::ChaCha20 => 32,
        EncryptionType::Aes256Gcm => 32,
    };
    dk.resize(key_len, 0);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt.as_bytes(), rounds, &mut dk);
    dk
}

pub fn normalize_end_encrypt_file_name(name: &str, encryption_type: &EncryptionType, key: &Vec<u8>) -> String {
    let mut normalized_name = name.replace("/", " ").replace("\\", " ");
    if normalized_name != "$." && normalized_name != "$.." {
        normalized_name = encrypt_string(&normalized_name, encryption_type, key);
        normalized_name = normalized_name.replace("/", "|");
    }
    normalized_name
}
