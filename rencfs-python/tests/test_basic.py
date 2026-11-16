import errno
import os

import pytest

from rencfs import Cipher, CreateFileAttr, EncryptedFs, FileType, SetFileAttr

ROOT_INO = 1
PASSWORD = "my_secure_password"


@pytest.fixture
def fs(tmp_path):
    return EncryptedFs(str(tmp_path), PASSWORD, Cipher.Aes256Gcm, False)


def file_attr():
    return CreateFileAttr(FileType.RegularFile, 0o644, 1000, 1000)


def dir_attr():
    return CreateFileAttr(FileType.Directory, 0o755, 1000, 1000)


def write_file(fs, name, data):
    handle, attr = fs.create(ROOT_INO, name, file_attr(), False, True)
    assert fs.write(attr.ino, 0, data, handle) == len(data)
    fs.flush(handle)
    fs.release(handle)
    return attr.ino


def read_file(fs, ino, size):
    handle = fs.open(ino, True, False)
    try:
        return fs.read(ino, 0, size, handle)
    finally:
        fs.release(handle)


def test_init(fs):
    assert fs.exists(ROOT_INO)
    assert fs.is_dir(ROOT_INO)


def test_create(fs):
    # create() returns (handle, attr), the inode is attr.ino
    handle, attr = fs.create(ROOT_INO, "testfile.txt", file_attr(), True, True)
    assert handle != 0
    assert attr.ino > ROOT_INO
    assert attr.kind == FileType.RegularFile
    assert fs.exists(attr.ino)
    assert fs.is_file(attr.ino)
    assert fs.is_write_handle(handle)
    fs.release(handle)


def test_create_dir_has_no_handle(fs):
    handle, attr = fs.create(ROOT_INO, "dir", dir_attr(), False, False)
    assert handle == 0
    assert fs.is_dir(attr.ino)


def test_read_write(fs):
    data = b"hello encrypted world!"
    ino = write_file(fs, "data.txt", data)
    assert fs.get_attr(ino).size == len(data)

    read_data = read_file(fs, ino, 100)
    assert isinstance(read_data, bytes)
    assert read_data == data


def test_write_larger_than_one_block(fs):
    # the core writes at most one 256 KB block per call, the binding must write everything
    data = os.urandom(1024 * 1024 + 123)
    ino = write_file(fs, "big.bin", data)
    assert fs.get_attr(ino).size == len(data)
    assert read_file(fs, ino, len(data)) == data


def test_read_is_clamped_to_file_size(fs):
    ino = write_file(fs, "small.txt", b"abc")
    assert read_file(fs, ino, 2**48) == b"abc"


def test_second_write_handle_is_rejected(fs):
    handle, attr = fs.create(ROOT_INO, "locked.txt", file_attr(), False, True)
    with pytest.raises(RuntimeError):
        fs.open(attr.ino, False, True)
    fs.release(handle)
    handle = fs.open(attr.ino, False, True)
    fs.release(handle)


def test_copy_file_range(fs):
    src = write_file(fs, "src.txt", b"0123456789")
    dest_handle, dest_attr = fs.create(ROOT_INO, "dest.txt", file_attr(), False, True)
    src_handle = fs.open(src, True, False)
    assert fs.copy_file_range(src, 2, dest_attr.ino, 0, 5, src_handle, dest_handle) == 5
    fs.flush(dest_handle)
    fs.release(dest_handle)
    fs.release(src_handle)
    assert read_file(fs, dest_attr.ino, 100) == b"23456"


def test_set_attr(fs):
    ino = write_file(fs, "attr.txt", b"x")
    fs.set_attr(ino, SetFileAttr(perm=0o600))
    assert fs.get_attr(ino).perm == 0o600


def test_read_dir_rename_remove(fs):
    ino = write_file(fs, "a.txt", b"x")
    assert [(e.name, e.ino) for e in fs.read_dir(ROOT_INO) if e.name == "a.txt"] == [("a.txt", ino)]

    fs.rename(ROOT_INO, "a.txt", ROOT_INO, "b.txt")
    assert not fs.exists_by_name(ROOT_INO, "a.txt")
    assert fs.find_by_name(ROOT_INO, "b.txt").ino == ino
    assert fs.find_by_name(ROOT_INO, "a.txt") is None

    fs.remove_file(ROOT_INO, "b.txt")
    assert not fs.exists(ino)


def test_errors(fs):
    write_file(fs, "dup.txt", b"x")
    with pytest.raises(FileExistsError):
        fs.create(ROOT_INO, "dup.txt", file_attr(), False, False)
    with pytest.raises(FileNotFoundError):
        fs.get_attr(424242)
    with pytest.raises(FileNotFoundError):
        fs.remove_file(ROOT_INO, "missing.txt")

    _, dir_ = fs.create(ROOT_INO, "dir", dir_attr(), False, False)
    fs.create(dir_.ino, "inner.txt", file_attr(), False, False)
    with pytest.raises(OSError) as err:
        fs.remove_dir(ROOT_INO, "dir")
    assert err.value.errno == errno.ENOTEMPTY

    with pytest.raises(OSError) as err:
        fs.release(424242)
    assert err.value.errno == errno.EBADF


def test_read_only(tmp_path):
    EncryptedFs(str(tmp_path), PASSWORD, Cipher.Aes256Gcm, False)
    fs = EncryptedFs(str(tmp_path), PASSWORD, Cipher.Aes256Gcm, True)
    with pytest.raises(PermissionError):
        fs.create(ROOT_INO, "x.txt", file_attr(), False, False)


def test_passwd(tmp_path):
    fs = EncryptedFs(str(tmp_path), PASSWORD, Cipher.Aes256Gcm, False)
    ino = write_file(fs, "keep.txt", b"still here")
    del fs

    with pytest.raises(PermissionError):
        EncryptedFs.passwd(str(tmp_path), "wrong", "new_password", Cipher.Aes256Gcm)
    EncryptedFs.passwd(str(tmp_path), PASSWORD, "new_password", Cipher.Aes256Gcm)

    with pytest.raises(PermissionError):
        EncryptedFs(str(tmp_path), PASSWORD, Cipher.Aes256Gcm, False)
    fs = EncryptedFs(str(tmp_path), "new_password", Cipher.Aes256Gcm, False)
    assert read_file(fs, ino, 100) == b"still here"


def test_set_len_read_dir_plus_remove_dir(fs):
    # moved from the old test_bindings.py smoke script
    ino = write_file(fs, "grow.txt", b"0123456789")
    fs.set_len(ino, 100)
    assert fs.get_attr(ino).size == 100
    fs.set_len(ino, 4)
    assert read_file(fs, ino, 100) == b"0123"

    entries = {e.name: e for e in fs.read_dir_plus(ROOT_INO)}
    assert entries["grow.txt"].ino == ino
    assert entries["grow.txt"].kind == FileType.RegularFile
    assert entries["grow.txt"].attr.size == 4

    _, dir_ = fs.create(ROOT_INO, "empty_dir", dir_attr(), False, False)
    assert fs.is_dir(dir_.ino)
    fs.remove_dir(ROOT_INO, "empty_dir")
    assert not fs.exists_by_name(ROOT_INO, "empty_dir")
    assert not fs.exists(dir_.ino)


def test_read_only_can_list_and_read(tmp_path):
    rw = EncryptedFs(str(tmp_path), PASSWORD, Cipher.Aes256Gcm, False)
    ino = write_file(rw, "ro.txt", b"read me")
    del rw

    ro = EncryptedFs(str(tmp_path), PASSWORD, Cipher.Aes256Gcm, True)
    assert [e.name for e in ro.read_dir(ROOT_INO) if e.name == "ro.txt"] == ["ro.txt"]
    assert [e.ino for e in ro.read_dir_plus(ROOT_INO) if e.name == "ro.txt"] == [ino]
    handle = ro.open(ino, True, False)
    assert ro.read(ino, 0, 100, handle) == b"read me"
    ro.release(handle)
    # the handle is gone after release
    assert not ro.is_read_handle(handle)


def test_copy_file_range_more_than_available(fs):
    src = write_file(fs, "src2.txt", b"0123456789")
    dest_handle, dest_attr = fs.create(ROOT_INO, "dest2.txt", file_attr(), False, True)
    fs.write(dest_attr.ino, 0, b"ab", dest_handle)
    src_handle = fs.open(src, True, False)
    # ask for far more than the source has, copy to a non-zero destination offset
    assert fs.copy_file_range(src, 6, dest_attr.ino, 2, 2**48, src_handle, dest_handle) == 4
    fs.flush(dest_handle)
    fs.release(dest_handle)
    fs.release(src_handle)
    assert read_file(fs, dest_attr.ino, 100) == b"ab6789"


def test_copy_file_range_multiple_blocks(fs):
    # larger than one 256 KB block so the core needs several writes
    data = os.urandom(600 * 1024 + 7)
    src = write_file(fs, "big_src.bin", data)
    dest_handle, dest_attr = fs.create(ROOT_INO, "big_dest.bin", file_attr(), False, True)
    src_handle = fs.open(src, True, False)
    assert fs.copy_file_range(src, 0, dest_attr.ino, 0, len(data), src_handle, dest_handle) == len(data)
    fs.flush(dest_handle)
    fs.release(dest_handle)
    fs.release(src_handle)
    assert read_file(fs, dest_attr.ino, len(data)) == data


def test_set_attr_timestamp_out_of_range(fs):
    ino = write_file(fs, "time.txt", b"x")
    # the core only moves timestamps forward, so use one in the future
    fs.set_attr(ino, SetFileAttr(mtime=4_000_000_000))
    assert fs.get_attr(ino).mtime == 4_000_000_000
    with pytest.raises(ValueError):
        fs.set_attr(ino, SetFileAttr(mtime=2**64 - 1))
