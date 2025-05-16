import os
import shutil
import pytest

def test_copy_video_integrity():
    """Test copying a video file and verifying its integrity."""
    src_path = "tmp_upload/video1.mp4"
    dest_path = "final/video1.mp4"
    
    os.makedirs("final", exist_ok=True)
    
    assert os.path.exists(src_path), "Source video does not exist!"
    
    shutil.copy(src_path, dest_path)
    
    assert os.path.exists(dest_path), "Copied video does not exist in final!"
    
    # Compare file sizes
    assert os.path.getsize(src_path) == os.path.getsize(dest_path), "File sizes do not match!"
    
    # Compare first 1KB of content
    with open(src_path, "rb") as src_file, open(dest_path, "rb") as dest_file:
        assert src_file.read(1024) == dest_file.read(1024), "File contents differ!"
