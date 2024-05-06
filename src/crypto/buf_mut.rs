use std::cmp::min;
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};

use secrecy::Zeroize;

pub struct BufMut {
    buf: Vec<u8>,
    pos: usize,
    read_pos: usize,
}

impl BufMut {
    pub fn new(from: Vec<u8>) -> Self {
        Self {
            buf: from,
            pos: 0,
            read_pos: 0,
        }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.pos]
    }

    pub fn as_mut_read(&mut self) -> &mut [u8] {
        &mut self.buf[self.pos..]
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    pub fn clear(&mut self) {
        self.pos = 0;
        self.read_pos = 0;
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn available(&self) -> usize {
        self.pos()
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
        match pos {
            SeekFrom::Start(pos) => {
                if pos as usize > self.buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "position is out of bounds",
                    ));
                }
                self.pos = pos as usize;
            }
            SeekFrom::End(pos) => {
                if (self.buf.len() as i64 + pos) < 0
                    || (self.buf.len() as i64 + pos) > self.buf.len() as i64
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "position is out of bounds",
                    ));
                }
                self.pos = (self.buf.len() as i64 + pos) as usize;
            }
            SeekFrom::Current(pos) => {
                if (self.pos as i64 + pos) < 0 || (self.pos as i64 + pos) > self.buf.len() as i64 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "position is out of bounds",
                    ));
                }
                self.pos = (self.pos as i64 + pos) as usize;
            }
        }
        Ok(self.pos as u64)
    }
}

impl Read for BufMut {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = min(self.pos() - self.read_pos, buf.len());
        if len == 0 {
            return Ok(0);
        }
        buf[..len].copy_from_slice(&self.buf[self.read_pos..self.read_pos + len]);
        self.read_pos += len;
        Ok(len)
    }
}

impl Drop for BufMut {
    fn drop(&mut self) {
        self.buf.zeroize()
    }
}
