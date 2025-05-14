import os
import pytest

def test_rename_image():
    """Test renaming img3.jpg to renamed_img3.jpg."""
    img_dir = "tmp_upload"
    old_name = "img3.jpg"
    new_name = "renamed_img3.jpg"
    old_path = os.path.join(img_dir, old_name)
    new_path = os.path.join(img_dir, new_name)
    
    assert os.path.exists(old_path), "Original image does not exist!"
    
    os.rename(old_path, new_path)
    
    assert not os.path.exists(old_path), "Old file still exists!"
    assert os.path.exists(new_path), "New file was not created!"
    
    os.rename(new_path, old_path)  # Revert to original state
