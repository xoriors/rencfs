use std::cmp::min;
use std::io;
use std::io::{Read, Write};

use num_format::{Locale, ToFormattedString};
use tracing::{debug, error, instrument, warn};

#[cfg(test)]
const BUF_SIZE: usize = 256 * 1024;
// 256 KB buffer, smaller for tests because they all run in parallel
#[cfg(not(test))]
const BUF_SIZE: usize = 1024 * 1024; // 1 MB buffer

#[instrument(skip(r, len), fields(len = len.to_formatted_string( & Locale::en)))]
pub fn seek_forward_exact(r: &mut impl Read, len: u64) -> io::Result<()> {
    debug!("");
    seek_forward(r, len, false)?;
    Ok(())
}

#[instrument(skip(r, len), fields(len = len.to_formatted_string( & Locale::en)))]
pub fn seek_forward<R: Read>(r: &mut R, len: u64, stop_on_eof: bool) -> io::Result<u64> {
    debug!("");
    if len == 0 {
        return Ok(0);
    }

    let mut buffer = vec![0; BUF_SIZE];
    let mut pos = 0_u64;
    loop {
        #[allow(clippy::cast_possible_truncation)]
        let read_len = if pos + buffer.len() as u64 > len {
            (len - pos) as usize
        } else {
            buffer.len()
        };
        if read_len == 0 {
            break;
        }
        let read = r.read(&mut buffer[..read_len]).map_err(|err| {
            error!(
                "error reading from file pos {} len {}",
                pos.to_formatted_string(&Locale::en),
                read_len.to_formatted_string(&Locale::en)
            );
            err
        })?;
        pos += read as u64;
        if pos == len {
            break;
        } else if read == 0 {
            if stop_on_eof {
                break;
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof",
            ));
        }
    }

    Ok(pos)
}

#[instrument(skip(r, w, len), fields(len = len.to_formatted_string(& Locale::en)))]
pub fn copy_exact(r: &mut impl Read, w: &mut impl Write, len: u64) -> io::Result<()> {
    debug!("");
    copy(r, w, len, false)?;
    Ok(())
}

#[instrument(skip(r, w, len), fields(len = len.to_formatted_string(& Locale::en)))]
pub fn copy(r: &mut impl Read, w: &mut impl Write, len: u64, stop_on_eof: bool) -> io::Result<u64> {
    debug!("");
    if len == 0 {
        return Ok(0);
    }
    let mut buffer = vec![0; BUF_SIZE];
    let mut read_pos = 0_u64;
    loop {
        #[allow(clippy::cast_possible_truncation)]
        let buf_len = min(buffer.len(), (len - read_pos) as usize);
        let read = r.read(&mut buffer[..buf_len]).map_err(|err| {
            error!(
                "error reading from file pos {} len {}",
                read_pos.to_formatted_string(&Locale::en),
                buf_len.to_formatted_string(&Locale::en)
            );
            err
        })?;
        w.write_all(&buffer[..read]).map_err(|err| {
            error!(
                "error writing to file pos {} len {}",
                read_pos.to_formatted_string(&Locale::en),
                buf_len.to_formatted_string(&Locale::en)
            );
            err
        })?;
        read_pos += read as u64;
        if read_pos == len {
            break;
        } else if read == 0 {
            if stop_on_eof {
                break;
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof",
            ));
        }
    }
    Ok(read_pos)
}

#[instrument(skip(w, len), fields(len = len.to_formatted_string(& Locale::en)))]
pub fn fill_zeros(w: &mut impl Write, len: u64) -> io::Result<()> {
    debug!("");
    if len == 0 {
        return Ok(());
    }
    let buffer = vec![0; BUF_SIZE];
    let mut written = 0_u64;
    loop {
        #[allow(clippy::cast_possible_truncation)]
        let buf_len = min(buffer.len(), (len - written) as usize);
        w.write_all(&buffer[..buf_len]).map_err(|err| {
            error!(
                "error writing to file pos {} len {}",
                written.to_formatted_string(&Locale::en),
                buf_len.to_formatted_string(&Locale::en)
            );
            err
        })?;
        written += buf_len as u64;
        if written == len {
            break;
        }
    }
    Ok(())
}
/// Read trying to fill the buffer but stops on eof
pub fn read(mut r: impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut read = 0;
    loop {
        let len = r.read(&mut buf[read..])?;
        if len == 0 {
            break;
        }
        read += len;
        if read == buf.len() {
            break;
        }
    }
    Ok(read)
}
