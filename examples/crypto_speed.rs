use std::env::args;
use std::fs::File;
use std::future::Future;
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use std::{fs, io};

use anyhow::Result;
use secrecy::{SecretString, SecretVec};

use rencfs::crypto;
use rencfs::crypto::writer::CryptoWriter;
use rencfs::crypto::Cipher;

#[tokio::main]
async fn main() -> Result<()> {
    let cipher = Cipher::Aes256Gcm;
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

    stream_speed(&path_in, &path_out, cipher, &key)?;
    println!();
    file_speed(&path_in, &path_out, cipher, key.clone())?;
    // println!();
    // let dir_path_out = format!(
    //     "/tmp/{}.dir.enc",
    //     Path::new(&path_in).file_name().unwrap().to_str().unwrap()
    // );
    // chunks_speed(&path_in, &dir_path_out, cipher, key.clone())?;

    Ok(())
}

fn speed<F>(f: F, label: &str, size: u64) -> io::Result<()>
where
    F: FnOnce() -> io::Result<()>,
{
    let start = Instant::now();
    f()?;
    let duration = start.elapsed();
    println!(
        "{label} duration = {:?}, speed MB/s {:.2}",
        duration,
        (size as f64 / duration.as_secs_f64()) / 1024.0 / 1024.0
    );
    Ok(())
}

async fn speed_async<F>(f: F, label: &str, size: u64) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    let start = Instant::now();
    f.await?;
    let duration = start.elapsed();
    println!(
        "{label} duration = {:?}, speed MB/s {}",
        duration,
        (size as f64 / duration.as_secs_f64()) / 1024.0 / 1024.0
    );
    Ok(())
}

fn check_hash(r1: &mut impl Read, r2: &mut (impl Read + ?Sized)) -> Result<()> {
    let hash1 = crypto::hash_reader(r1)?;
    let hash2 = crypto::hash_reader(r2)?;
    assert_eq!(hash1, hash2);
    Ok(())
}

fn stream_speed(
    path_in: &str,
    path_out: &str,
    cipher: Cipher,
    key: &Arc<SecretVec<u8>>,
) -> Result<()> {
    println!("stream speed");
    let _ = fs::remove_file(path_out);
    let mut file_in = File::open(path_in)?;
    let file_out = File::create(path_out)?;
    let mut writer = crypto::create_writer(file_out, cipher, key.clone());
    let size = file_in.metadata()?.len();
    let f = || crypto::create_reader(File::open(path_out).unwrap(), cipher, key.clone());
    test_speed(&mut file_in, &mut writer, size, f)?;
    file_in.seek(io::SeekFrom::Start(0))?;
    check_hash(&mut file_in, &mut f())?;
    fs::remove_file(path_out)?;
    Ok(())
}

fn file_speed(
    path_in: &str,
    path_out: &str,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
) -> Result<()> {
    println!("file speed");
    let _ = fs::remove_file(path_out);
    let mut file_in = File::open(path_in)?;
    let mut writer = crypto::create_file_writer(
        &Path::new(&path_out).to_path_buf(),
        cipher,
        key.clone(),
        None,
        None,
        None,
    )?;
    let size = file_in.metadata()?.len();
    let f = || {
        crypto::create_file_reader(
            &Path::new(&path_out).to_path_buf(),
            cipher,
            key.clone(),
            None,
        )
        .unwrap()
    };
    test_speed(&mut file_in, &mut *writer, size, f)?;
    file_in.seek(io::SeekFrom::Start(0)).unwrap();
    check_hash(&mut file_in, &mut *f())?;
    // fs::remove_file(path_out)?;
    Ok(())
}

fn test_speed<W: Write, R: Read, FR>(
    r: &mut impl Read,
    w: &mut (impl CryptoWriter<W> + ?Sized),
    size: u64,
    r2: FR,
) -> io::Result<()>
where
    FR: FnOnce() -> R,
{
    let mut r = io::BufReader::new(r);
    let mut w = io::BufWriter::new(w);
    speed(
        || {
            io::copy(&mut r, &mut w)?;
            w.flush()?;
            w.into_inner()
                .map_err(|err| {
                    let (err, _) = err.into_parts();
                    err
                })?
                .finish()?;
            Ok(())
        },
        "write",
        size,
    )?;
    speed(
        || {
            io::copy(&mut r2(), &mut io::sink())?;
            Ok(())
        },
        "read",
        size,
    )?;
    Ok(())
}

fn get_key(cipher: Cipher) -> io::Result<SecretVec<u8>> {
    let password = SecretString::new("pass42".to_string());
    let salt = crypto::hash_secret_string(&password);
    Ok(crypto::derive_key(&password, cipher, salt).unwrap())
}
