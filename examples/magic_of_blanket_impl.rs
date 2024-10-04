/// This demonstrates the magic of blanket implementation.
///
/// If we have a wrapper that wraps [Read] we don't have access to [Seek::seek] method, but
/// if we wrap [Read] + [Seek] we do.
/// We use this in [rencfs::crypto::read] and also in [rencfs::crypto::write].
use std::io;
use std::io::{Read, Seek, SeekFrom};

fn main() {
    // wrap only Read
    let mut reader = MyRead { inner: OnlyRead {} };
    println!("we can read");
    let _ = reader.read(&mut [0; 10]).unwrap();
    // but we cannot seek
    // reader.seek(SeekFrom::Start(0)).unwrap(); // compile error

    // wrap Read + Seek
    let mut reader_seek = MyRead { inner: ReadSeek {} };
    println!("we can read");
    let _ = reader_seek.read(&mut [0; 10]).unwrap();
    println!("we can seek too");
    reader_seek.seek(SeekFrom::Start(0)).unwrap();
}

struct MyRead<R: Read> {
    inner: R,
}

struct OnlyRead {}
impl Read for OnlyRead {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

struct ReadSeek {}
impl Read for ReadSeek {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}
impl Seek for ReadSeek {
    fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
        Ok(0)
    }
}

impl<R: Read> Read for MyRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read + Seek> Seek for MyRead<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}
