import os
import pytest

def test_verify_image_files():
    """Test Case 6: Verify that all JPG files exist and are valid images."""
    img_files = ["img1.jpg", "img2.jpg", "img3.jpg", "img4.jpg"]
    img_dir = "tmp_upload"

    for img in img_files:
        img_path = os.path.join(img_dir, img)

        # Step 1: Check if file exists
        assert os.path.exists(img_path), f"Image {img} does not exist!"

        # Step 2: Attempt to open and verify the image
        try:
            with Image.open(img_path) as im: # type: ignore
                im.verify()  # Verify image integrity
        except Exception as e:
            pytest.fail(f"Invalid image file {img}: {e}")

    print("All image files exist and are valid.")

    # Undo step: No destructive operations performed, no cleanup needed
    print("Undo: No actions required for image validation.")
