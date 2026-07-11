import pytest
import os
import shutil
from rencfs import EncryptedFs, Cipher, CreateFileAttr, FileType

@pytest.fixture
def test_dir():
    path = "./test_data"
    os.makedirs(path, exist_ok=True)
    yield path
    shutil.rmtree(path, ignore_errors=True)

def test_encryptedfs_init(test_dir):
    # This should create the structure inside test_dir
    fs = EncryptedFs(test_dir, "my_secure_password", Cipher.Aes256Gcm, False)
    assert fs is not None

def test_encryptedfs_create(test_dir):
    fs = EncryptedFs(test_dir, "my_secure_password", Cipher.Aes256Gcm, False)
    
    # ROOT_INO is typically 1. We create a file under root.
    attr = CreateFileAttr(FileType.RegularFile, 0o644, 1000, 1000)
    handle, ret_attr = fs.create(1, "testfile.txt", attr, True, True)

    assert ret_attr.ino > 1
    assert fs.exists(ret_attr.ino)
    assert fs.is_file(ret_attr.ino)

def test_encryptedfs_read_write(test_dir):
    fs = EncryptedFs(test_dir, "my_secure_password", Cipher.Aes256Gcm, False)
    attr = CreateFileAttr(FileType.RegularFile, 0o644, 1000, 1000)
    handle, ret_attr = fs.create(1, "data.txt", attr, True, True)
    ino = ret_attr.ino

    # Open for write
    fh = fs.open(ino, False, True)
    assert fh > 0
    
    # Write data
    data = b"hello encrypted world!"
    written = fs.write(ino, 0, data, fh)
    assert written == len(data)
    
    # Flush and Release
    fs.flush(fh)
    fs.release(fh)
    
    # Open for read
    fh2 = fs.open(ino, True, False)
    
    # Read data
    read_data = fs.read(ino, 0, 100, fh2)
    assert read_data == data
    
    fs.release(fh2)
