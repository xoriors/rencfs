#ifndef RENCFS_H
#define RENCFS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Pointer opac catre structura Rust
typedef struct RencfsContext RencfsContext;

// Initializeaza sistemul. Returneaza NULL la eroare.
RencfsContext* rencfs_init(const char* base_path, const char* password);

// Elibereaza memoria.
void rencfs_free(RencfsContext* ctx);

// Creeaza un fisier. Returneaza 0 la succes.
int rencfs_create_file(RencfsContext* ctx, const char* filename, uint64_t* out_ino, uint64_t* out_handle);

// Creeaza un director. Returneaza 0 la succes.
int rencfs_mkdir(RencfsContext* ctx, uint64_t parent_ino, const char* filename, uint64_t* out_ino);

// Sterge un fisier.
int rencfs_unlink(RencfsContext* ctx, uint64_t parent_ino, const char* filename);

// Sterge un director (rmdir). Returneaza 0 la succes.
int rencfs_rmdir(RencfsContext* ctx, uint64_t parent_ino, const char* filename);

// Redenumeste/Muta un fisier.
int rencfs_rename(RencfsContext* ctx, uint64_t parent, const char* old_name, uint64_t new_parent, const char* new_name);
// Scrie in fisier.
int rencfs_write(RencfsContext* ctx, uint64_t ino, uint64_t handle, const unsigned char* buf, size_t len, uint64_t offset);

// Citeste din fisier.
int rencfs_read(RencfsContext* ctx, uint64_t ino, uint64_t handle, unsigned char* buf, size_t len, uint64_t offset);

// Inchide fisierul.
int rencfs_close(RencfsContext* ctx, uint64_t handle);

#ifdef __cplusplus
}
#endif

#endif
