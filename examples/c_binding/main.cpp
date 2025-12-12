#include <iostream>
#include <vector>
#include <cstring>
#include "rencfs.h"

int main() {
    std::cout << "--- Rencfs C++ Binding Demo ---" << std::endl;

    // 1. Initializare
    const char* path = "/tmp/rencfs_cpp_test";
    const char* pass = "parola_mea_secreta";

    std::cout << "[CPP] Initializing rencfs at " << path << "..." << std::endl;
    RencfsContext* ctx = rencfs_init(path, pass);

    if (!ctx) {
        std::cerr << "[CPP] Failed to init rencfs!" << std::endl;
        return 1;
    }
    std::cout << "[CPP] Init success!" << std::endl;

    // 2. Create File
    uint64_t ino = 0;
    uint64_t handle = 0;
    const char* filename = "fisier_secret.txt";

    std::cout << "[CPP] Creating file: " << filename << std::endl;
    if (rencfs_create_file(ctx, filename, &ino, &handle) != 0) {
        std::cerr << "[CPP] Failed to create file!" << std::endl;
        rencfs_free(ctx);
        return 1;
    }
    std::cout << "[CPP] Created! Inode: " << ino << ", Handle: " << handle << std::endl;

    // 3. Write Data
    const char* message = "Salut din C++ catre Rust Encrypted FS!";
    size_t len = strlen(message);
    std::cout << "[CPP] Writing: " << message << std::endl;

    int written = rencfs_write(ctx, ino, handle, (const unsigned char*)message, len, 0);
    std::cout << "[CPP] Bytes written: " << written << std::endl;

    // 4. Close (flush)
    std::cout << "[CPP] Closing file (flush)..." << std::endl;
    rencfs_close(ctx, handle);

    // 5. Test MKDIR (Facem folderul pe care il vom sterge la final)
    uint64_t dir_ino = 0;
    std::cout << "[CPP] Creating directory 'my_secrets'..." << std::endl;
    if (rencfs_mkdir(ctx, 1, "my_secrets", &dir_ino) == 0) {
        std::cout << "[CPP] Directory created! Inode: " << dir_ino << std::endl;
    } else {
        std::cerr << "[CPP] Mkdir failed!" << std::endl;
    }

    // 6. Test RENAME
    const char* new_filename = "redenumit_secret.txt";
    std::cout << "[CPP] Renaming '" << filename << "' to '" << new_filename << "'..." << std::endl;
    if (rencfs_rename(ctx, 1, filename, 1, new_filename) == 0) {
        std::cout << "[CPP] Rename success!" << std::endl;
    } else {
        std::cerr << "[CPP] Rename failed!" << std::endl;
    }

    // 7. Test UNLINK (Stergem fisierul redenumit)
    std::cout << "[CPP] Deleting file '" << new_filename << "'..." << std::endl;
    if (rencfs_unlink(ctx, 1, new_filename) == 0) {
        std::cout << "[CPP] File deleted successfully!" << std::endl;
    } else {
        std::cerr << "[CPP] Unlink failed!" << std::endl;
    }

    // 8. Test RMDIR (Stergem directorul creat la pasul 5)
    std::cout << "[CPP] Removing directory 'my_secrets'..." << std::endl;
    if (rencfs_rmdir(ctx, 1, "my_secrets") == 0) {
        std::cout << "[CPP] Rmdir success!" << std::endl;
    } else {
        std::cerr << "[CPP] Rmdir failed!" << std::endl;
    }

    // 9. Cleanup
    std::cout << "[CPP] Freeing context..." << std::endl;
    rencfs_free(ctx);

    std::cout << "[CPP] Done." << std::endl;
    return 0;
}
