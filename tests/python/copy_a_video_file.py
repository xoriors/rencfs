import os
import shutil
import pytest

def test_copy_video():
    """Test copying video3.mp4 from tmp_upload to final."""
    src_dir = "tmp_upload"
    dest_dir = "final"
    file_name = "video3.mp4"
    src_path = os.path.join(src_dir, file_name)
    dest_path = os.path.join(dest_dir, file_name)
    
    os.makedirs(dest_dir, exist_ok=True)
    
    assert os.path.exists(src_path), "Source video does not exist!"
    
    shutil.copy(src_path, dest_path)
    
    assert os.path.exists(src_path), "Original file should not be deleted!"
    assert os.path.exists(dest_path), "File was not copied to destination!"
    
    os.remove(dest_path)
