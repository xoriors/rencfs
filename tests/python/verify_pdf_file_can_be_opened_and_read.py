import os
import pytest
from PyPDF2 import PdfReader

def test_read_pdf():
    """Test if a PDF file can be opened and read."""
    pdf_path = "tmp_upload/pdf1.pdf"
    
    assert os.path.exists(pdf_path), "PDF file does not exist!"
    
    with open(pdf_path, "rb") as f:
        reader = PdfReader(f)
        assert len(reader.pages) > 0, "PDF file has no pages!"
