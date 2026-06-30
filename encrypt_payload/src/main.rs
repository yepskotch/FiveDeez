//! encrypt_payload — standalone helper tool
//!
//! Usage:
//!   encrypt_payload <raw_shellcode.bin> <hex_key_64chars> <hex_nonce_24chars> <output.bin>
//!
//! Arguments:
//!   raw_shellcode.bin   — path to raw shellcode bytes
//!   hex_key_64chars     — 64 hex chars = 32 bytes AES-256 key
//!   hex_nonce_24chars   — 24 hex chars = 12 bytes GCM nonce
//!   output.bin          — path to write the encrypted output file
//!
//! The output file is raw AES-256-GCM ciphertext (payload + 16-byte tag).
//! It is read and decrypted at runtime by the loader using the KEY and NONCE
//! baked into the compiled binary.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use std::{env, fs, process};

fn decode_hex(s: &str, expected_bytes: usize, label: &str) -> Vec<u8> {
    if s.len() != expected_bytes * 2 {
        eprintln!(
            "[!] {} must be {} hex chars ({} bytes), got {}",
            label,
            expected_bytes * 2,
            expected_bytes,
            s.len()
        );
        process::exit(1);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| {
                eprintln!("[!] Invalid hex in {}: {}", label, &s[i..i + 2]);
                process::exit(1);
            })
        })
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: encrypt_payload <shellcode.bin> <hex_key_64> <hex_nonce_24> <output.bin>");
        process::exit(1);
    }

    let input_path  = &args[1];
    let hex_key     = &args[2];
    let hex_nonce   = &args[3];
    let output_path = &args[4];

    let plaintext = fs::read(input_path).unwrap_or_else(|e| {
        eprintln!("[!] Failed to read '{}': {}", input_path, e);
        process::exit(1);
    });

    if plaintext.is_empty() {
        eprintln!("[!] Shellcode file '{}' is empty.", input_path);
        process::exit(1);
    }

    let key_bytes   = decode_hex(hex_key,   32, "KEY");
    let nonce_bytes = decode_hex(hex_nonce, 12, "NONCE");

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce  = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap_or_else(|e| {
        eprintln!("[!] Encryption failed: {}", e);
        process::exit(1);
    });

    fs::write(output_path, &ciphertext).unwrap_or_else(|e| {
        eprintln!("[!] Failed to write '{}': {}", output_path, e);
        process::exit(1);
    });

    eprintln!("    Plaintext : {} bytes", plaintext.len());
    eprintln!("    Ciphertext: {} bytes (payload + 16-byte GCM tag)", ciphertext.len());
    eprintln!("    Output    : {}", output_path);
}
