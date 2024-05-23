use std::cmp::min;
use std::io;
use std::io::{Read, SeekFrom, Write};

use secrecy::Zeroize;

pub struct BufMut {
    buf: Vec<u8>,
    pos_write: usize,
    pos_read: usize,
    available: usize,
    dirty: bool,
}

impl BufMut {
    #[must_use]
    pub fn new(from: Vec<u8>) -> Self {
        Self {
            buf: from,
            pos_write: 0,
            pos_read: 0,
            available: 0,
            dirty: false,
        }
    }

    /// Remaining for write from the write position to the end of the buffer
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos_write
    }

    /// Returns a slice of the buffer with space available for writing, that is from the write position to the end of the buffer
    pub fn as_mut_remaining(&mut self) -> &mut [u8] {
        &mut self.buf[self.available..]
    }

    pub fn clear(&mut self) {
        self.pos_write = 0;
        self.pos_read = 0;
        self.available = 0;
        self.dirty = false;
    }

    #[must_use]
    pub const fn available(&self) -> usize {
        self.available
    }

    #[must_use]
    pub const fn available_read(&self) -> usize {
        self.available() - self.pos_read
    }

    /// Seek the read position
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    pub fn seek_read(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::End(pos) => self.buf.len() as i64 + pos,
            SeekFrom::Current(pos) => self.pos_read as i64 + pos,
        };
        if new_pos < 0 || new_pos > self.available() as i64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("position is out of bounds {new_pos}/{}", self.available()),
            ));
        }
        self.pos_read = new_pos as usize;
        Ok(self.pos_read as u64)
    }

    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    pub fn seek_write(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::End(pos) => self.buf.len() as i64 + pos,
            SeekFrom::Current(pos) => self.pos_write as i64 + pos,
        };
        if new_pos < 0 || new_pos > self.buf.len() as i64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("position is out of bounds {new_pos}/{}", self.buf.len()),
            ));
        }
        self.pos_write = new_pos as usize;
        self.available = self.pos_write.max(self.available);
        Ok(self.pos_write as u64)
    }

    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    pub fn seek_available(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::End(pos) => self.buf.len() as i64 + pos,
            SeekFrom::Current(pos) => self.available as i64 + pos,
        };
        if new_pos < 0 || new_pos > self.buf.len() as i64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("position is out of bounds {new_pos}/{}", self.buf.len()),
            ));
        }
        // keep write in bounds
        self.available = new_pos as usize;
        self.pos_write = self.pos_write.min(self.available);
        // keep read in bounds
        self.pos_read = self.pos_read.min(self.available);
        Ok(self.available as u64)
    }

    #[must_use]
    pub const fn pos_read(&self) -> usize {
        self.pos_read
    }

    #[must_use]
    pub const fn pos_write(&self) -> usize {
        self.pos_write
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Returns a slice of the buffer with content available for reading
    #[must_use]
    pub fn as_ref_read_available(&self) -> &[u8] {
        &self.buf[self.pos_read..self.available]
    }

    /// If we wrote something to the buffer since it was created or cleared
    #[must_use]
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }
}

impl AsMut<[u8]> for BufMut {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.available]
    }
}

impl AsRef<[u8]> for BufMut {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.available]
    }
}

impl Write for BufMut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = min(self.remaining(), buf.len());
        if len == 0 {
            return Ok(0);
        }
        self.buf[self.pos_write..self.pos_write + len].copy_from_slice(&buf[..len]);
        self.pos_write += len;
        self.available = self.pos_write.max(self.available);
        self.dirty = true;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for BufMut {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = min(self.available_read(), buf.len());
        if len == 0 {
            return Ok(0);
        }
        buf[..len].copy_from_slice(&self.buf[self.pos_read..self.pos_read + len]);
        self.pos_read += len;
        Ok(len)
    }
}

impl Drop for BufMut {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use std::io::SeekFrom;

    use super::*;

    #[test]
    fn test_available() {
        let buf = BufMut::new(vec![0; 10]);
        assert_eq!(buf.available(), 0);
    }

    #[test]
    fn test_available_read() {
        let buf = BufMut::new(vec![0; 10]);
        assert_eq!(buf.available_read(), 0);
    }

    #[test]
    fn test_remaining() {
        let buf = BufMut::new(vec![0; 10]);
        assert_eq!(buf.remaining(), 10);
    }

    #[test]
    fn test_seek_write() {
        let mut buf = BufMut::new(vec![0; 10]);
        assert_eq!(buf.seek_write(SeekFrom::Start(5)).unwrap(), 5);
        assert_eq!(buf.pos_write(), 5);
    }

    #[test]
    fn test_seek_available() {
        let mut buf = BufMut::new(vec![0; 10]);
        assert_eq!(buf.seek_available(SeekFrom::Start(5)).unwrap(), 5);
        assert_eq!(buf.available(), 5);
    }

    #[test]
    fn test_pos_read() {
        let buf = BufMut::new(vec![0; 10]);
        assert_eq!(buf.pos_read(), 0);
    }

    #[test]
    fn test_pos_write() {
        let buf = BufMut::new(vec![0; 10]);
        assert_eq!(buf.pos_write(), 0);
    }

    #[test]
    fn test_write() {
        let mut buf = BufMut::new(vec![0; 10]);
        let written = buf.write(&[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(written, 5);
        assert_eq!(buf.pos_write(), 5);
        assert!(buf.is_dirty());
    }

    #[test]
    fn test_read() {
        let mut buf = BufMut::new(vec![1, 2, 3, 4, 5, 0, 0, 0, 0, 0]);
        buf.seek_write(SeekFrom::Start(10)).unwrap();
        let mut read_buf = [0; 3];
        buf.read_exact(&mut read_buf).unwrap();
        assert_eq!(read_buf, [1, 2, 3]);
        assert_eq!(buf.pos_read(), 3);
    }

    #[test]
    fn test_seek_read() {
        let mut buf = BufMut::new(vec![1, 2, 3, 4, 5, 0, 0, 0, 0, 0]);
        buf.seek_write(SeekFrom::Start(5)).unwrap();
        buf.seek_read(SeekFrom::Start(2)).unwrap();
        let mut read_buf = [0; 3];
        buf.read_exact(&mut read_buf).unwrap();
        assert_eq!(read_buf, [3, 4, 5]);
        assert_eq!(buf.pos_read(), 5);
    }

    #[test]
    fn test_complex_write_read_seek() {
        let mut buf = BufMut::new(vec![0; 10]);

        // Write some data
        let written = buf.write(&[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(written, 5);
        assert_eq!(buf.pos_write(), 5);
        assert_eq!(buf.available(), 5);

        // Seek back to the start
        assert_eq!(buf.seek_read(SeekFrom::Start(0)).unwrap(), 0);

        // Read the data
        let mut read_buf = [0; 5];
        buf.read_exact(&mut read_buf).unwrap();
        assert_eq!(read_buf, [1, 2, 3, 4, 5]);
        assert_eq!(buf.pos_read(), 5);

        // Write some more data
        let written = buf.write(&[6, 7, 8, 9, 10]).unwrap();
        assert_eq!(written, 5);
        assert_eq!(buf.pos_write(), 10);
        assert_eq!(buf.available(), 10);

        // Seek back to the start
        assert_eq!(buf.seek_read(SeekFrom::Start(0)).unwrap(), 0);
        assert_eq!(buf.pos_write(), 10);
        assert_eq!(buf.available(), 10);

        // Read all the data
        let mut read_buf = [0; 10];
        buf.read_exact(&mut read_buf).unwrap();
        assert_eq!(read_buf, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(buf.pos_read(), 10);
    }

    #[test]
    fn test_write_larger_than_buffer() {
        let mut buf = BufMut::new(vec![0; 10]);
        let data = vec![1; 10 + 10];
        let written = buf.write(&data).unwrap();
        assert_eq!(written, 10);
        assert_eq!(buf.pos_write(), 10);
        assert_eq!(buf.available(), 10);
        assert_eq!(buf.remaining(), 0);
        buf.seek_write(SeekFrom::Start(0)).unwrap();
        assert!(buf.write_all(&[1; 11]).is_err());
    }

    #[test]
    fn test_read_larger_than_buffer() {
        let data = vec![1; 10 + 10];
        let mut buf = BufMut::new(data.clone());
        buf.seek_write(SeekFrom::Start(20)).unwrap();
        buf.seek_read(SeekFrom::Start(10_u64)).unwrap();
        let mut read_buf = vec![0; 10 + 10];
        let read = buf.read(&mut read_buf).unwrap();
        assert_eq!(read, 10);
        assert_eq!(read_buf[..10], data[10..20]);
        assert_eq!(buf.pos_read(), 20);
        buf.seek_read(SeekFrom::Start(0)).unwrap();
        assert!(buf.read_exact(&mut [1; 21]).is_err());
    }

    #[test]
    fn test_seek_write_out_of_bounds() {
        let mut buf = BufMut::new(vec![0; 10]);
        assert!(buf.seek_write(SeekFrom::Start(11)).is_err());
        assert!(buf.seek_write(SeekFrom::End(1)).is_err());
        assert!(buf.seek_write(SeekFrom::End(-11)).is_err());
        assert!(buf.seek_write(SeekFrom::Current(11)).is_err());
        assert!(buf.seek_write(SeekFrom::Current(-1)).is_err());
    }

    #[test]
    fn test_seek_read_out_of_bounds() {
        let mut buf = BufMut::new(vec![0; 10]);
        assert!(buf.seek_read(SeekFrom::Start(11)).is_err());
        assert!(buf.seek_read(SeekFrom::End(1)).is_err());
        assert!(buf.seek_read(SeekFrom::End(-11)).is_err());
        assert!(buf.seek_read(SeekFrom::Current(6)).is_err());
        assert!(buf.seek_read(SeekFrom::Current(-1)).is_err());
    }

    #[test]
    fn test_seek_available_out_of_bounds() {
        let mut buf = BufMut::new(vec![0; 10]);
        assert!(buf.seek_available(SeekFrom::Start(11)).is_err());
        assert!(buf.seek_available(SeekFrom::End(1)).is_err());
        assert!(buf.seek_available(SeekFrom::End(-11)).is_err());
        assert!(buf.seek_available(SeekFrom::Current(11)).is_err());
        assert!(buf.seek_available(SeekFrom::Current(-1)).is_err());
    }
}
