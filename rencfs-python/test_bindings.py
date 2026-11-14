import rencfs
import tempfile
import os

def test_basic_operations():
    # Create a temporary directory for the encrypted filesystem data
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = os.path.join(tmpdir, "data")
        os.makedirs(data_dir, exist_ok=True)
        
        password = "testpassword123"
        cipher = rencfs.Cipher.ChaCha20Poly1305
        read_only = False
        
        # Initialize the encrypted filesystem
        fs = rencfs.EncryptedFs(data_dir, password, cipher, read_only)
        print("Initialized EncryptedFs")
        
        # Root inode is 1
        root_ino = 1
        assert fs.exists(root_ino), "Root inode should exist"
        assert fs.is_dir(root_ino), "Root inode should be a directory"
        print("Root inode checks passed")
        
        # Create a file in the root directory
        parent = root_ino
        name = "testfile.txt"
        attr = rencfs.CreateFileAttr(
            kind=rencfs.FileType.RegularFile,
            perm=0o644,
            uid=0,
            gid=0,
            rdev=0
        )
        read = True
        write = True
        
        # The create method returns a tuple (handle, FileAttr)
        handle, file_attr = fs.create(parent, name, attr, read, write)
        ino = file_attr.ino
        print(f"Created file '{name}' with inode {ino}, handle {handle}")
        
        # If we got a handle (non-zero), we should release it because we don't need to keep it open
        if handle != 0:
            fs.release(handle)
            print(f"Released handle {handle}")
        
        # Verify the file exists and is a file
        assert fs.exists(ino), f"Inode {ino} should exist"
        assert fs.is_file(ino), f"Inode {ino} should be a file"
        assert not fs.is_dir(ino), f"Inode {ino} should not be a directory"
        
        # Get the file attributes to verify initial size is 0
        file_attr = fs.get_attr(ino)
        print(f"Initial file attributes: ino={file_attr.ino}, size={file_attr.size}")
        assert file_attr.size == 0, f"Expected initial size 0, got {file_attr.size}"
        
        # Write some data to the file
        # Open the file for writing
        handle = fs.open(ino, read=False, write=True)
        print(f"Opened file for writing with handle {handle}")
        
        write_data = b"Hello, rencfs! This is a test."
        written = fs.write(ino, 0, write_data, handle)
        assert written == len(write_data), f"Expected to write {len(write_data)} bytes, got {written}"
        print(f"Wrote {written} bytes")
        
        # Flush and release the handle
        fs.flush(handle)
        fs.release(handle)
        print("Flushed and released write handle")
        
        # Open the file for reading
        handle = fs.open(ino, read=True, write=False)
        print(f"Opened file for reading with handle {handle}")
        
        # Read the data back (returns a list of integers)
        read_data_list = fs.read(ino, 0, len(write_data), handle)
        read_data = bytes(read_data_list)
        assert read_data == write_data, f"Read data mismatch: expected {write_data}, got {read_data}"
        print(f"Read back: {read_data}")
        
        # Release the read handle
        fs.release(handle)
        print("Released read handle")
        
        # Check file size after write
        file_attr = fs.get_attr(ino)
        print(f"File attributes after write: ino={file_attr.ino}, size={file_attr.size}")
        assert file_attr.size == len(write_data), f"Expected size {len(write_data)}, got {file_attr.size}"
        
        # Test setting attributes (e.g., change size via truncate)
        new_size = 100
        fs.set_len(ino, new_size)
        file_attr = fs.get_attr(ino)
        print(f"After setting size to {new_size}: size={file_attr.size}")
        assert file_attr.size == new_size, f"Expected size {new_size}, got {file_attr.size}"
        
        # Read directory and see the file
        entries = fs.read_dir_plus(parent)
        found = False
        for entry in entries:
            if entry.name == name:
                found = True
                assert entry.ino == ino, f"Inode mismatch: expected {ino}, got {entry.ino}"
                # Check that the attributes match
                assert entry.attr.ino == ino, f"Attr inode mismatch: expected {ino}, got {entry.attr.ino}"
                assert entry.attr.size == file_attr.size, f"Attr size mismatch: expected {file_attr.size}, got {entry.attr.size}"
                break
        assert found, f"File {name} not found in directory listing"
        print(f"Found file {name} in directory listing with correct attributes")
        
        # Rename the file
        new_name = "renamed.txt"
        fs.rename(parent, name, parent, new_name)
        print(f"Renamed {name} to {new_name}")
        
        # Check that the old name is gone and the new name exists
        assert not fs.exists_by_name(parent, name), f"Old name {name} should not exist"
        assert fs.exists_by_name(parent, new_name), f"New name {new_name} should exist"
        
        # Find by the new name
        opt_attr = fs.find_by_name(parent, new_name)
        assert opt_attr is not None, f"Should find attributes for {new_name}"
        found_attr = opt_attr
        assert found_attr.ino == ino, f"Inode mismatch: expected {ino}, got {found_attr.ino}"
        print(f"Found attributes for renamed file: inode {found_attr.ino}")
        
        # Remove the file
        fs.remove_file(parent, new_name)
        print(f"Removed file {new_name}")
        
        # Check that it's gone
        assert not fs.exists_by_name(parent, new_name), f"Removed file {new_name} should not exist"
        assert not fs.exists(ino), f"Inode {ino} should not exist"
        
        # Test creating a directory
        dir_name = "testdir"
        dir_attr = rencfs.CreateFileAttr(
            kind=rencfs.FileType.Directory,
            perm=0o755,
            uid=0,
            gid=0,
            rdev=0
        )
        
        dir_ino, dir_attr_out = fs.create(parent, dir_name, dir_attr, read=True, write=True)
        print(f"Created directory '{dir_name}' with inode {dir_ino}, handle {dir_ino} (handle is actually 0 for dirs)")
        # For directories, the handle returned is 0 (since we don't open a handle)
        assert dir_ino == 0, "Expected handle 0 for directory creation"
        
        # The actual directory inode is in dir_attr_out.ino
        dir_ino_actual = dir_attr_out.ino
        print(f"Directory inode is {dir_ino_actual}")
        
        assert fs.exists(dir_ino_actual), f"Directory inode {dir_ino_actual} should exist"
        assert fs.is_dir(dir_ino_actual), f"Directory inode {dir_ino_actual} should be a directory"
        assert not fs.is_file(dir_ino_actual), f"Directory inode {dir_ino_actual} should not be a file"
        
        # List the directory again to see the new directory
        entries = fs.read_dir_plus(parent)
        dir_found = False
        for entry in entries:
            if entry.name == dir_name:
                dir_found = True
                assert entry.ino == dir_ino_actual, f"Directory inode mismatch: expected {dir_ino_actual}, got {entry.ino}"
                break
        assert dir_found, f"Directory {dir_name} not found in directory listing"
        print(f"Found directory {dir_name} in directory listing")
        
        # Remove the directory
        fs.remove_dir(parent, dir_name)
        print(f"Removed directory {dir_name}")
        
        assert not fs.exists_by_name(parent, dir_name), f"Removed directory {dir_name} should not exist"
        assert not fs.exists(dir_ino_actual), f"Directory inode {dir_ino_actual} should not exist"
        
        # Test password change (optional)
        new_password = "newpassword456"
        # We'll change the password and then try to reopen the filesystem with the new password
        # Note: the passwd method is static on the EncryptedFs class
        rencfs.EncryptedFs.passwd(data_dir, password, new_password, cipher)
        print("Password changed successfully")
        
        # Now try to open the filesystem with the new password
        fs_new = rencfs.EncryptedFs(data_dir, new_password, cipher, read_only)
        print("Opened filesystem with new password")
        
        # The root should still exist
        assert fs_new.exists(root_ino), "Root inode should exist after password change"
        assert fs_new.is_dir(root_ino), "Root inode should be a directory after password change"
        print("Root still accessible after password change")
        
        # Create a new file to verify the filesystem is working
        name2 = "testfile2.txt"
        attr2 = rencfs.CreateFileAttr(
            kind=rencfs.FileType.RegularFile,
            perm=0o644,
            uid=0,
            gid=0,
            rdev=0
        )
        
        handle2, file_attr2 = fs_new.create(parent, name2, attr2, read=True, write=True)
        ino2 = file_attr2.ino
        assert fs_new.exists(ino2), "New file should exist after password change"
        print(f"Created new file '{name2}' with inode {ino2} after password change")
        
        # Clean up the new file
        if handle2 != 0:
            fs_new.release(handle2)
        fs_new.remove_file(parent, name2)
        
        print("All tests passed!")

if __name__ == "__main__":
    test_basic_operations()
