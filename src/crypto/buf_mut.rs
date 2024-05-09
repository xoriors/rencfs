use std::cmp::min;
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};

use secrecy::Zeroize;

pub struct BufMut {
    buf: Vec<u8>,
    pos: usize,
    pos_read: usize,
}

impl BufMut {
    pub fn new(from: Vec<u8>) -> Self {
        Self {
            buf: from,
            pos: 0,
            pos_read: 0,
        }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.pos]
    }

    pub fn as_mut_remaining(&mut self) -> &mut [u8] {
        &mut self.buf[self.pos..]
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    pub fn clear(&mut self) {
        self.pos = 0;
        self.pos_read = 0;
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn pos_read(&self) -> usize {
        self.pos_read
    }

    pub fn available(&self) -> usize {
        self.pos()
    }

    pub fn available_read(&self) -> usize {
        self.available() - self.pos_read
    }
}

impl Write for BufMut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = min(self.remaining(), buf.len());
        self.buf[self.pos..self.pos + len].copy_from_slice(&buf[..len]);
        self.pos += len;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for BufMut {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::End(pos) => self.buf.len() as i64 + pos,
            SeekFrom::Current(pos) => self.pos as i64 + pos,
        };
        if new_pos < 0 || new_pos > self.buf.len() as i64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "position is out of bounds",
            ));
        }
        self.pos = new_pos as usize;
        Ok(self.pos as u64)
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
        self.buf.zeroize()
    }
}
