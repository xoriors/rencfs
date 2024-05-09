use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;

use base64::read;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use rencfs::crypto;
use rencfs::crypto::writer::{CryptoWriter, FileCryptoWriterCallback};
use rencfs::crypto::Cipher;
use rencfs::encryptedfs::FsError;

fn key_serialize<S>(key: &SecretVec<u8>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.collect_seq(key.expose_secret())
}

fn key_unserialize<'de, D>(deserializer: D) -> Result<SecretVec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
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

fn main() -> anyhow::Result<()> {
    let password = SecretString::new("pass42".to_string());
    let salt = crypto::hash_secret_string(&password);
    let cipher = Cipher::ChaCha20;
    let key = Arc::new(crypto::derive_key(&password, &cipher, salt).unwrap());

    let reader = crypto::create_reader(
        File::open("/home/gnome/rencfs_data/security/key.enc").unwrap(),
        &cipher,
        key.clone(),
        42,
    );
    let key_store: KeyStore =
        bincode::deserialize_from(reader).map_err(|_| FsError::InvalidPassword)?;
    let key = Arc::new(key_store.key);

    let path_in = "/home/gnome/Downloads/jetbrains-toolbox-2.2.1.19765.tar.gz";
    let path_out = "/tmp/jetbrains-toolbox-2.2.1.19765.tar.gz";
    // let path_in = "/home/gnome/tmp/1";
    // let path_out = "/tmp/1";
    let out = Path::new(&path_out).to_path_buf();
    if out.exists() {
        std::fs::remove_file(&out)?;
    }
    // let path_in = "/home/gnome/Downloads/99cff0fd-d05a-43f1-a214-e0512ae2576b.jpeg";
    // let path_out = "/tmp/99cff0fd-d05a-43f1-a214-e0512ae2576b.jpeg";

    struct CallbackImpl {}
    impl FileCryptoWriterCallback for CallbackImpl {
        fn on_file_content_changed(
            &self,
            changed_from_pos: u64,
            last_write_pos: u64,
        ) -> io::Result<()> {
            Ok(())
        }
    }
    let mut file = File::open(path_in).unwrap();
    let mut writer = crypto::create_file_writer(
        Path::new(&path_out).to_path_buf(),
        Path::new(&"/tmp").to_path_buf(),
        cipher,
        key.clone(),
        3927180043778011763,
        CallbackImpl {},
    )?;

    let mut buf = vec![0; 1024];
    loop {
        let len = file.read(&mut buf).unwrap();
        if len == 0 {
            break;
        }
        writer.write_all(&buf[..len]).unwrap();
    }
    writer.flush().unwrap();
    writer.finish().unwrap();

    let mut reader = crypto::create_file_reader(
        Path::new(&path_out).to_path_buf(),
        cipher,
        key.clone(),
        3927180043778011763,
    )?;
    reader.seek(io::SeekFrom::Start(1000));
    reader.seek(io::SeekFrom::Start(0));
    let hash1 = crypto::hash_reader(File::open(path_in).unwrap());
    let hash2 = crypto::hash_reader(&mut reader);
    reader.finish()?;

    assert_eq!(hash1, hash2);

    Ok(())
}
