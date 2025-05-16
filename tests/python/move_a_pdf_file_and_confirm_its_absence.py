import os
import shutil
import pytest

def test_move_pdf():
    """Test moving pdf2.pdf from tmp_upload to final."""
    src_dir = "tmp_upload"
    dest_dir = "final"
    file_name = "pdf2.pdf"
    src_path = os.path.join(src_dir, file_name)
    dest_path = os.path.join(dest_dir, file_name)
    
    os.makedirs(dest_dir, exist_ok=True)
    
    assert os.path.exists(src_path), "Source PDF does not exist!"
    
    shutil.move(src_path, dest_path)
    
    assert not os.path.exists(src_path), "File was not removed from source directory!"
    assert os.path.exists(dest_path), "File was not moved to destination directory!"
    
    os.remove(dest_path)
