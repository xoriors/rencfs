use std::env::args;
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;

use secrecy::SecretString;

use rencfs::crypto;
use rencfs::crypto::writer::FileCryptoWriterCallback;
use rencfs::crypto::Cipher;

fn main() -> anyhow::Result<()> {
    let password = SecretString::new("password".to_string());
    let salt = crypto::hash_secret_string(&password);
    let cipher = Cipher::ChaCha20;
    let key = Arc::new(crypto::derive_key(&password, cipher, salt).unwrap());

    let mut args = args();
    let path_in = args.next().expect("path_in is missing");
    let path_out = format!(
        "/tmp/{}.enc",
        Path::new(&path_in).file_name().unwrap().to_str().unwrap()
    );
    let out = Path::new(&path_out).to_path_buf();
    if out.exists() {
        std::fs::remove_file(&out)?;
    }

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
    let mut file = File::open(path_in.clone()).unwrap();
    let mut writer = crypto::create_file_writer(
        &Path::new(&path_out).to_path_buf(),
        &Path::new(&"/tmp").to_path_buf(),
        cipher,
        key.clone(),
        42_u64,
        CallbackImpl {},
    )?;
    io::copy(&mut file, &mut writer).unwrap();
    writer.flush().unwrap();
    writer.finish().unwrap();

    let mut reader = crypto::create_file_reader(
        &Path::new(&path_out).to_path_buf(),
        cipher,
        key.clone(),
        42_u64,
    )?;
    let hash1 = crypto::hash_reader(File::open(path_in).unwrap());
    let hash2 = crypto::hash_reader(&mut reader);

    assert_eq!(hash1, hash2);

    Ok(())
}
