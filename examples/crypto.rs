use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;

use secrecy::SecretString;

use rencfs::crypto;
use rencfs::crypto::writer::{CryptoWriter, FileCryptoWriterCallback};
use rencfs::crypto::Cipher;

fn main() -> anyhow::Result<()> {
    let password = SecretString::new("password".to_string());
    let salt = crypto::hash_secret_string(&password);
    let cipher = Cipher::ChaCha20;
    let key = Arc::new(crypto::derive_key(&password, &cipher, salt).unwrap());

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
        274004967328880354,
        CallbackImpl {},
    )?;
    io::copy(&mut file, &mut writer).unwrap();
    writer.flush().unwrap();
    writer.finish().unwrap();

    let mut reader = crypto::create_file_reader(
        Path::new(&path_out).to_path_buf(),
        cipher,
        key.clone(),
        274004967328880354,
    )?;
    let hash1 = crypto::hash_reader(File::open(path_in).unwrap());
    let hash2 = crypto::hash_reader(&mut reader);

    assert_eq!(hash1, hash2);

    Ok(())
}
