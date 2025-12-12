#include <iostream>
#include <vector>
#include <cstring>
#include "rencfs.h"

int main() {
    std::cout << "--- Rencfs C++ Binding Demo ---" << std::endl;

    // 1. Initializare
    // ATENTIE: Asigura-te ca folderul /tmp/rencfs_test exista sau e un loc unde se poate scrie
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

    // 5. Open/Read (pentru simplitate in demo, presupunem ca il citim cu un handle nou sau ne-am baza pe open,
    // dar aici doar inchidem contextul pentru a arata cleanup-ul).

    // 6. Cleanup
    std::cout << "[CPP] Freeing context..." << std::endl;
    rencfs_free(ctx);

    std::cout << "[CPP] Done." << std::endl;
    return 0;
}
