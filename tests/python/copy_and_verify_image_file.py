import os
import shutil
import filecmp

def test_copy_image_file():
    source = "tmp_upload/img1.jpg"
    dest_dir = "final"
    dest = os.path.join(dest_dir, "img1.jpg")

    os.makedirs(dest_dir, exist_ok=True)

    try:
        shutil.copy2(source, dest)
        assert os.path.exists(dest), "Image file was not copied."
        assert filecmp.cmp(source, dest, shallow=False), "Copied image content mismatch."
        print("✅ Test passed: Image copied and verified.")
    except AssertionError as e:
        print(f"❌ Test failed: {e}")
    finally:
        # Clean up
        if os.path.exists(dest):
            os.remove(dest)
