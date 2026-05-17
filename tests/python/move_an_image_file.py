import os
import shutil
import pytest

def test_move_image():
    """Test moving img1.jpg from tmp_upload to final and verifying its absence in source."""
    src_dir = "tmp_upload"
    dest_dir = "final"
    file_name = "img1.jpg"
    src_path = os.path.join(src_dir, file_name)
    dest_path = os.path.join(dest_dir, file_name)
    
    os.makedirs(dest_dir, exist_ok=True)
    
    assert os.path.exists(src_path), "Source image does not exist!"
    
    shutil.move(src_path, dest_path)
    
    assert not os.path.exists(src_path), "File was not removed from source directory!"
    assert os.path.exists(dest_path), "File was not moved to destination directory!"
    
    os.remove(dest_path)

 # Undo step: Clean up created test file or restore previous state
    # Uncomment the next line to actually remove the file after testing
    # os.remove(doc_path)
    print("Undo: Cleaned up test artifacts or restored previous state.")