import os

def test_verify_doc():
    """Test if text1.doc exists, is not empty, and has a valid .doc extension."""
    doc_path = "tmp_upload/text1.doc"
    
    # Check if file exists
    assert os.path.exists(doc_path), f"Error: {doc_path} does not exist!"
    
    # Check if file is not empty
    file_size = os.path.getsize(doc_path)
    assert file_size > 0, f"Error: {doc_path} is empty!"
    
    # Additional check: Ensure it has a .doc extension
    assert doc_path.lower().endswith(".doc"), f"Error: {doc_path} does not have a .doc extension!"
    
    print(f"Test passed: {doc_path} exists, is not empty ({file_size} bytes), and has a valid extension.")

