import os
import pytest

def test_delete_doc():
    """Test deleting text1.doc from tmp_upload."""
    doc_path = "tmp_upload/text1.doc"
    
    assert os.path.exists(doc_path), "DOC file does not exist!"
    
    os.remove(doc_path)
    
    assert not os.path.exists(doc_path), "DOC file was not deleted!"
