use std::cmp::min;
use std::io;
use std::io::{Read, Write};
use num_format::{Locale, ToFormattedString};
use tracing::{debug, instrument};

#[cfg(test)]
const BUF_SIZE: usize = 256 * 1024;
// 256 KB buffer, smaller for tests because they all run in parallel
#[cfg(not(test))]
const BUF_SIZE: usize = 1024 * 1024; // 1 MB buffer

#[instrument(skip(r, len), fields(len = len.to_formatted_string( & Locale::en)))]
pub fn read_seek_forward_exact(mut r: impl Read, len: u64) -> io::Result<()> {
    debug!("");
    if len == 0 {
        return Ok(());
    }

    let mut buffer = vec![0; BUF_SIZE];
    let mut pos = 0_u64;
    loop {
        let read_len = if pos + buffer.len() as u64 > len {
            (len - pos) as usize
        } else {
            buffer.len()
        };
        debug!(read_len = read_len.to_formatted_string(&Locale::en), "reading");
        if read_len > 0 {
            r.read_exact(&mut buffer[..read_len])?;
            pos += read_len as u64;
            if pos == len {
                break;
            }
        } else {
            break;
        }
    }

    Ok(())
}

#[instrument(skip(r, w, len), fields(len = len.to_formatted_string(& Locale::en)))]
pub fn copy_exact(r: &mut impl Read, w: &mut impl Write, len: u64) -> io::Result<()> {
    debug!("");
    if len == 0 {
        return Ok(());
    }
    let mut buffer = vec![0; BUF_SIZE];
    let mut read_pos = 0_u64;
    loop {
        let buf_len = min(buffer.len(), (len - read_pos) as usize);
        debug!("reading from file pos {} buf_len {}", read_pos.to_formatted_string(&Locale::en), buf_len.to_formatted_string(&Locale::en));
        r.read_exact(&mut buffer[..buf_len]).map_err(|err| {
            debug!("error reading from file pos {} len {}",  read_pos.to_formatted_string(&Locale::en), buf_len.to_formatted_string(&Locale::en));
            err
        })?;
        w.write_all(&buffer[..buf_len])?;
        read_pos += buf_len as u64;
        if read_pos == len {
            break;
        }
    }
    Ok(())
}