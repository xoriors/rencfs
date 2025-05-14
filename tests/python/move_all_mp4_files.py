import os
import shutil

def test_move_videos():
    """Test moving all .mp4 files from tmp_upload to final and verifying their absence."""
    src_dir = "tmp_upload"
    dest_dir = "final"
    video_files = ["video1.mp4", "video2.mp4", "video3.mp4"]
    
    os.makedirs(dest_dir, exist_ok=True)
    
    for video in video_files:
        src_path = os.path.join(src_dir, video)
        dest_path = os.path.join(dest_dir, video)
        
        assert os.path.exists(src_path), f"Source file {video} does not exist!"
        shutil.move(src_path, dest_path)
        assert not os.path.exists(src_path), f"{video} was not removed from source directory!"
        assert os.path.exists(dest_path), f"{video} was not moved to destination directory!"
        
        os.remove(dest_path)

# Undo step: Clean up created test file or restore previous state
    # Uncomment the next line to actually remove the file after testing
    # os.remove(doc_path)
    print("Undo: Cleaned up test artifacts or restored previous state.")  
