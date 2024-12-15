use rencfs::crypto::Cipher;
use shush_rs::SecretString;
use std::io::SeekFrom;
use std::path::Path;
use std::str::FromStr;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
// use tokio::fs::OpenOptions;
use rencfs::crypto::fs_api::r#async::fs::OpenOptions;
use rencfs::encryptedfs::PasswordProvider;

static ROOT_CIPHER_FS_DATA_DIR: &str = "/tmp/rencfs/file_layer/fs_cipher";
static FILENAME: &str = "test1";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_fs().await?;

    cleanup().await;
    let file_path = Path::new(FILENAME).to_path_buf();

    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&file_path)
        .await
        .unwrap();

    // let mut opts = OpenOptions::new();
    // // add static flags
    // let opts = opts.read(true).write(true);
    // // add dynamic flags
    // let opts = _add_create(opts, &file_path);
    // let mut file = opts.open(&file_path).await.unwrap();

    file.write_all(b"test42").await.unwrap();
    file.flush().await.unwrap();
    file.shutdown().await.unwrap();

    file.seek(SeekFrom::End(0)).await.unwrap();
    eprintln!("size {}", file.stream_position().await.unwrap());

    file.seek(SeekFrom::Start(0)).await.unwrap();

    let mut buf = String::new();
    let len = file.read_to_string(&mut buf).await.unwrap();
    println!("{len} {buf}");

    Ok(())
}

async fn init_fs() -> anyhow::Result<()> {
    OpenOptions::init_scope(
        Path::new(ROOT_CIPHER_FS_DATA_DIR).to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
        false,
    )
    .await?;
    Ok(())
}

fn _add_create<'a>(opts: &'a mut OpenOptions, path: &Path) -> &'a mut OpenOptions {
    if !path.to_path_buf().exists() {
        opts.create(true);
    }
    opts
}

async fn cleanup() {
    // todo: ignore if we delete first time when not present
    let _ = tokio::fs::remove_dir_all(Path::new(ROOT_CIPHER_FS_DATA_DIR)).await;

    // // todo: seems we need to abstract also Path because exists() goes against local FS
    // if file_path.exists() {
    //     fs::remove_file(&file_path).await.unwrap();
    // }
}

struct PasswordProviderImpl {}

impl PasswordProvider for PasswordProviderImpl {
    fn get_password(&self) -> Option<SecretString> {
        Some(SecretString::from_str("pass42").unwrap())
    }
}
