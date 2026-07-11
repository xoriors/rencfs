use crate::crypto::write::CryptoWrite; // Resolves the error with .finish()
use crate::crypto::{self, Cipher};
use shush_rs::SecretVec;
use std::io::{Cursor, Read, Write, Error, ErrorKind, Result};
use std::sync::Mutex; // Required for reusable decryption buffer

pub struct IpfsCipher {
    key: SecretVec<u8>,
    cipher: Cipher,
    dec_buffer: Mutex<Vec<u8>>, // Reusable buffer for decryption
}

impl IpfsCipher {
    /// Initializes the plugin with a secure key and the default cipher
    pub fn new(secret_key: Vec<u8>) -> Self {
        // Validate key length to prevent downstream library panics (Point 3 in review)
        assert_eq!(
            secret_key.len(), 
            32, 
            "Invalid key length for ChaCha20Poly1305. Expected exactly 32 bytes."
        );

        Self {
            key: SecretVec::from(secret_key),
            cipher: Cipher::ChaCha20Poly1305,
            dec_buffer: Mutex::new(Vec::with_capacity(1024 * 64)), // Pre-allocate 64KB
        }
    }

    /// Encrypts a block of data using a Cursor to simulate an in-memory file
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // Pre-allocate capacity matching data size to satisfy 'static bounds without reallocation churn
        let estimated_capacity = data.len() + 256;
        let memory_file = Cursor::new(Vec::with_capacity(estimated_capacity));
        let mut writer = crypto::create_write(memory_file, self.cipher, &self.key);

        writer
            .write_all(data)
            .map_err(|e| Error::new(ErrorKind::Other, format!("Error writing IPFS data: {:?}", e)))?;

        // .finish() returns the internal object (the Cursor) on success
        let finished_cursor = writer
            .finish()
            .map_err(|e| Error::new(ErrorKind::Other, format!("Error finalizing IPFS encryption: {:?}", e)))?;

        // Extract the byte vector from the inner cursor
        Ok(finished_cursor.into_inner())
    }

    /// Decrypts a block of data using the native CryptoRead from rencfs
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.is_empty() {
            return Ok(Vec::new());
        }

        let mut buffer_guard = self.dec_buffer.lock().map_err(|_| {
            Error::new(ErrorKind::Other, "Failed to lock decryption buffer lock")
        })?;
        buffer_guard.clear();

        let mut reader = crypto::create_read(encrypted_data, self.cipher, &self.key);

        reader
            .read_to_end(&mut *buffer_guard)
            .map_err(|e| Error::new(ErrorKind::Other, format!("Error decrypting IPFS data: {:?}", e)))?;

        Ok(buffer_guard.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipfs_encryption_decryption() {
        // Generate a 32-byte test key (required for ChaCha20Poly1305)
        let test_key = vec![0u8; 32];
        let cipher = IpfsCipher::new(test_key);

        let original_data = b"Secret data sent via IPFS with a unique CID!";

        // 1. Encrypt the data
        let encrypted = cipher.encrypt(original_data).expect("Encryption failed");
        assert_ne!(
            original_data.to_vec(),
            encrypted,
            "Encrypted data must not match the original data"
        );

        // 2. Decrypt the data back
        let decrypted = cipher.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(
            original_data.to_vec(),
            decrypted,
            "Decrypted data does not match the original data"
        );
    }

    #[test]
    #[should_panic(expected = "Invalid key length")]
    fn test_invalid_key_length_panics() {
        // Test that an invalid key length triggers the validation assert
        let short_key = vec![0u8; 16];
        let _cipher = IpfsCipher::new(short_key);
    }
}