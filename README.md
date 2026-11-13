# Deterministic filesystem access on Switch 2 (fw 23.0.1) via Civ 7's embedded Lua

Research notes on reaching a working, blocking **fsp-srv** IPC channel — and live
filesystem reads — on Switch 2 firmware **23.0.1**, using the `nora2hax/seedsow`
save-file exploit against Civilization 7's embedded Lua engine.

This is a technical write-up of an exploitation *path* and the obstacles solved
along the way. It contains no firmware, no keys, and no copyrighted content.

---

## TL;DR

- `nora2hax/seedsow` gives deterministic Lua code execution (`n2h` primitive)
  inside Civ 7 on fw 23.0.1 — no race, no save-geometry lottery.
- The historical blocker for both this and the CivSwitch (chat-XSS) path was the
  same: **no working thread creation / no block-capable execution context**, so a
  blocking `svcSendSyncRequest` to fsp-srv would hang forever.
- **That wall is now broken.** Raw-svc kernel threads were brought up and proven
  on hardware; a real kernel thread *can* block/resume where the forged
  `call_deep` context cannot.
- On a raw-svc thread: `GetServiceHandle("fsp-srv")` → a valid session →
  `SetCurrentProcess` round-trips (`SFCO`, `cmif_result = 0`) →
  `OpenDataStorageByCurrentProcess` → `IStorage::GetSize` returns a real size.
- **Result: deterministic, authenticated, blocking filesystem IPC over Seedsow,
  reading real data back.** The transport is complete and HW-proven.

---

## Target identification

"Seedsow" / codename "Ounce" is **Civilization 7** — the same installed title
that CivSwitch exploits via chat-XSS. Seedsow instead exploits Civ 7's *embedded
Lua* (Civ 7's scripts are Lua). Same installed game, same nnSdk build. Proof: the
longjmp and `svcCreateThread` offsets are identical to the CivSwitch Civ 7 probe.

- Civ 7 mounts (chat-XSS path): `['rom','save','cache']`
- Seedsow/Lua host mounts: `['game','save']`

Same nnSdk 23.0.1; game-specific details (mount names, allocation costs) differ.

---

## Entry / transport

`nora2hax/seedsow` runs an HTTP server on the console at **:8080**:

- `POST /eval` — run Lua
- `PUT/POST /save`, `DELETE /delete`

A small Python client posts Lua files to `/eval`. The entry drops after any
crash and must be relaunched (re-arm the save exploit on the console).

### The `n2h` Lua primitive (global, verified on HW)

`peek`/`poke` (64-bit), `write_bytes` (exact), `alloc`/`free`,
`call_deep(func, a0..a4)` → x0, `run_chain`/`new_emitter` (gadget chains),
`addrof`/`str_addr`, `gadgets`, `offsets_sdk` (32 entries), `offsets_main`,
`main_base`, `sdk_base`, `platform = "Ounce"`. Sockets are present too
(`bind`/`listen`/`accept`/`recv`/`send`, **no `connect`**).

---

## Hard constraints (each cost real crashes to learn)

- **`peek` on `.text` segfaults the process** — code pages are X-only. Only ever
  *call* `.text` via `call_deep`; never read it. peek/write are safe only on
  owned RW memory.
- **Lua 5.1 = doubles.** Any value ≥ 2^53 (e.g. a 64-bit word with the top bits
  set) loses precision through `peek`. This produces a notorious "everything
  reads as `0x3`" artifact in reply buffers and struct reads. Precise 32-bit
  read: memmove 4 bytes into a zeroed 8-aligned scratch, then `peek` (< 2^32 is
  exact). Lua 5.1 also means no `\xNN` string escapes — use `string.char`.
- **Alignment-aware 32-bit reads:** read the 8-aligned word at `x - (x % 8)`; low
  half if `x % 8 == 0`, high half if `x % 8 == 4`. A naive
  `floor(peek(x-4) / 2^32)` is wrong for 8-aligned `x`.
- **The TLS message buffer is volatile past its first 8 bytes.** `write_bytes` to
  TLS self-clobbers (its memcpy routes through TLS); `peek` itself disturbs the
  TLS. You cannot stage-and-verify a request in TLS from sequential Lua.
- **`svcQueryMemory` MemoryInfo layout on Switch 2 fw23 is non-standard** — base
  at +0 is correct, but the size/type/perm fields are not at the classic offsets
  (they read `0x3` via the Lua-precision artifact). Must be re-derived before any
  region-guard use. The current-thread pseudo-handle borrow avoids needing it.

---

## Offsets (from the dumped sdk NSO — symbols intact), sdk_base-relative

Service manager / IPC:

- `nn::sm::GetServiceHandle` = **+0x14cc90** (`out*, name*, len` → Result)
- `nn::sm::Initialize` = +0x14cb20
- `get_message_buffer_on_tls` = +0x14ba80 (`mrs x0, tpidrro_el0; ret`)
- `svcSendSyncRequest` (TLS) = +0x168c4c (`svc #0x21`)
- `svcSendSyncRequestWithUserBuffer` = +0x168c54 (`svc #0x22`)

SVC wrappers:

- `svcMapMemory` +0x168afc, `svcUnmapMemory` +0x168b04, `svcQueryMemory` +0x168b0c
- `svcCreateThread` +0x168b2c, `svcStartThread` +0x168b44, `svcExitThread`
  +0x168b4c (note: **not** +0x168b24 = ExitProcess)
- `svcGetThreadPriority` +0x168b5c, `svcGetThreadCoreMask` +0x168b7c,
  `svcGetCurrentProcessorNumber` +0x168ba4
- `svcWaitSynchronization` +0x168bf4, `svcCloseHandle` +0x168be4,
  `svcGetInfo` +0x168ca4, `svcConnectToNamedPort` +0x168c34
- `svcWaitForAddress` +0x168d1c, `svcSignalToAddress` +0x168d24
- `longjmp` +0x5511b4, `memmove` +0x522830

Non-svc gadget offsets (live build): `loadTable` 0x4E094, `call4` 0x359b88,
`saveResult64` 0x19bcc0, `call4LoadOffset` = 112. (Note: earlier published
configs list call4 at 0x359BC8 / saveResult64 at 0x19B6C0 — those are stale for
this build. Verify against the current dump; you can't verify on-device because
`.text` peeks crash.)

Sockets: socket +0x14d4c0, bind +0x14d3b0, listen +0x14d440, accept +0x14d380,
recv +0x14d300, send +0x14d350, close +0x14d510, fcntl +0x14d560,
is_initialized +0x14d930 (Civ 7 already initializes sockets — no
`socket_initialize` needed).

---

## The thread-creation wall — and how it was broken

### Why it mattered

A *valid*, blocking `svcSendSyncRequest` / `WithUserBuffer` never completes from
any forged context: on the main/HTTP thread (`call_deep` or `run_chain`) it
blocks and never resumes — the forged ROP/JOP context can't survive a kernel
block+resume. The normal fix (a worker thread) crashed on hardware. Both the
Seedsow and CivSwitch paths converged on this single unsolved problem.

### What did NOT work

- nn::os high-level `CreateThread` out-of-context → deadlocks then crashes (its
  constructors / alias-map / ThreadManager locks don't tolerate a forged entry).
- The old worker_probe pattern forged a thread with a raw heap stack and called
  the thread-impl directly, skipping the alias stack — Ryujinx doesn't enforce
  memory type so it passed in emulation, but real HW `svcCreateThread` rejects a
  heap stack.
- Blind iteration was the real wall for a while: `/eval` buffers all output, so a
  crash returns nothing. `n2h.log` goes to the kernel debug log (invisible
  without a HW debugger). Every failed attempt was a silent crash + re-arm.

### Two unlocks

1. **Debuggability via incremental `/eval`.** A step-gated harness runs the same
   Lua with an injected `__STOP_AT__ = N` bound. A run that returns "ok" proves
   steps 1..N survive; the first bound that returns nothing is the crashing step.
   This turns silent-crash into binary-search localization — no HW debugger
   needed.
2. **The crashes were the `.text` reads, not the thread logic.** The reference
   probe scans `.text` for byte-signatures; Seedsow code pages are X-only so any
   such scan crashes. Porting `.text`-free (using the offline NSO offsets
   directly) removes the crash.

### HW-proven raw-svc thread technique (Phase A, 3/3 clean)

- **Plain owned type-5 RW stack** from `N.alloc` (page-aligned manually), 0x14000
  bytes. No alias stack, no `svcMapMemory`.
- **Borrow a valid priority + core mask** from the current-thread pseudo-handle
  `0xFFFF8000` via `svcGetThreadPriority` / `svcGetThreadCoreMask`. A *forged*
  priority was the original cause of `0xE001` / crashes. No ThreadManager walk
  (that global is unmapped on this sdk build — skip it). Fall back to priority 44
  if a pool thread reports 0.
- **Entry = `longjmp` (+0x5511b4)** with a jmp_buf frame: `frame+0x58` = target
  PC, `frame+0x68` = stackTop. Zero the jmp_buf slots first (`N.alloc` doesn't
  zero).
- `call_deep` forwards all 6 args (x5 = core got through), so **no call6/emitter
  is needed** — the supposed porting hurdle was a non-issue.

Create → start → join (generous timeout) → close, process stays alive.

### Phase B (3/3) — run a native CALL on the raw-svc thread

A worker frame: `longjmp → loadTable → call4 → target → saveResult64 →
svcExitThread`. Sentinels kept < 2^53 for Lua double precision. The frame calls
`target(x0=[frame+0x30], x1=[sp+0x10], x2=[sp+0x20], x3=[sp+0x28])`. Verified by
running `memmove` and confirming the side-effect; thread joined clean. Result
*capture* (`saveResult64`) past call 0 is unreliable (stores a bogus value) but
the calls *execute* fine — verify by side-effects/replies, not captured results.

---

## Blocking fsp-srv IPC — the whole point

### Phase C: the hang is defeated

On the raw-svc thread: `GetServiceHandle("fsp-srv")` → valid handle; stage a CMIF
request in a page-aligned buffer; run the send on the thread. The thread **joins
clean** — the exact send that hangs forever from `call_deep`/main returns on a
real thread.

### The `0xf601` detour

Both the user-buffer send (`svc #0x22`) and the TLS send (`svc #0x21`) initially
returned `0xf601` = kernel module 1, desc 123 = **InvalidCombination**. Root
cause: the CMIF request must live in the **sending thread's own TLS**. The
user-buffer variant unmaps the buffer to use it as the IPC region and a heap
buffer isn't acceptable; and staging into a TLS slot from the main thread then
reusing it on a new thread fails too — the kernel zeroes/reassigns the TLS slot
on the new thread.

### The fix: multi-call worker chain on ONE thread

Port the engine's frame-builder to Lua: a chain of `loadTable → call4 →
saveResult64` frames (STEP 0x140, a result region, table/stack regions), with
**dynamic args** handled by an inserted `memmove` that copies a computed value
into the next call's arg slot. The full IPC chain on one raw-svc thread:

```
get_message_buffer_on_tls  →  memmove(dst=<TLS>, src=buf, len)  →  svcSendSyncRequest(handle)
```

Main stages the CMIF request in `buf`; the thread copies it into its *own* TLS
and sends. The reply lands in TLS; main reads it after join (precise 32-bit
reads).

### Clean round-trip (3/3 after a fresh re-arm)

`SetCurrentProcess` (cmd 1 + send-pid descriptor) over the raw-svc-thread CMIF
channel returns a valid CMIF response: `word0 = 0` (Response), `word1 = 8`,
**`SFCO` magic at TLS+0x10, `cmif_result = 0x0`**. The fsp-srv session is
initialized with the injected pid — a working, authenticated, blocking fs IPC
channel on a real thread.

HIPC response parse (standard): `w0`/`w1` at `tls+0`/`+4`; if `w1 >= 0x80000000`
there's a special header at `+8` (send-pid bit0, copies bits1-4, moves bits5-8),
handles follow; align to 16; `SFCO` magic there, `cmif_result` at `SFCO+8`, u64
payload at `SFCO+16`.

Multi-command sessions confirmed: a 5-logical-call chain runs two fsp-srv
commands in one session, both round-trip.

---

## Filesystem access achieved

- `OpenDataStorageByCurrentProcess` (cmd 200) → reply with a moved **IStorage**
  handle (`w1 = 0x80000008`), `cmif_result = 0`. (`OpenSdCardFileSystem` cmd 18
  fails `0xbfb20002` = no sdcard permission at Civ 7's own perms, as expected.)
- Two-thread flow: T1 opens the storage, main extracts the IStorage move-handle
  from T1's TLS reply (handle at `TLS+0xc`), T2 sends **`IStorage::GetSize`
  (cmd 4)** to that handle → `cmif_result = 0`, size ≈ 1.7 GB.

So: open a real FS object, get its handle, issue IStorage commands, read real
data back — all deterministically, over Civ 7's embedded Lua on raw-svc threads.
**This is the stated goal: working deterministic filesystem access.**

---

## Concurrency for the acquisition race

Raw-svc threads run **truly concurrently** on this console: 4 threads each
sleeping 1 s finish in ~1.1 s total, all join clean, with 4 distinct consecutive
TLS slots (kernel assigns TLS sequentially, 0x200 apart). This makes the
reserved-gap "wave" model (≈13 concurrent worker threads) viable.

Pattern for N concurrent threads: build N worker frames, loop
create+start (no join between), then join each at the end with a generous
timeout. Timing sync via staggered `svcSleepThread` delays per role (300 µs
steps dominate the µs-scale create/start skew), or a master-flag futex.

**Master-sync gotcha:** the eq1 wait wrapper expects the address in **x19**, not
x0; call `svcWaitForAddress` (+0x168d1c) directly with
`x0=addr, x1=arb_type(2), x2=value(1), x3=timeout(-1)`, or drop the futex and use
staggered sleeps.

---

## Where it stands / what's left

- **Transport: DONE and HW-proven** — raw-svc threads, multi-call worker frames
  with dynamic args, blocking authenticated fsp-srv IPC with reply parsing, live
  IStorage reads, and proven thread concurrency.
- **Remaining:** port the fs-bug *acquisition* stage (the reserved-gap race:
  staggered concurrent worker threads issuing the role IPCs so a canary alloc
  lands in the freed reservation group during an in-flight large commit), then
  the standard post-acquisition escalation. That escalation (arbitrary
  fs-process R/W → chosen-pid re-init → opening system filesystems) is the
  published method and is a large multi-session assembly; the deterministic
  channel to drive it is complete.

### Note on the CivSwitch (chat-XSS) sibling path

The CivSwitch/Civ 7 engine reaches the acquisition race and the overwrite
primitive qualifies (with the right fill-segment constant), but its cache-alias
*leak* currently returns 0 native-pointer candidates: the over-read lands on
Civ 7's **encrypted/compressed save-data cache** (entropy ~7.0–7.9 bits/byte),
not native allocator pages. Moving the alias offset only breaks alias selection;
it doesn't relocate the leak. Retargeting *what* memory the cache-alias maps to
(so the over-read lands on plaintext native-FS metadata) is the real crux there —
and is exactly what the deterministic Seedsow channel sidesteps.

---

*Credits to the upstream scene projects: `nora2hax/seedsow`, the `ns2jb` fs-bug
work, and the CivSwitch effort. Posted as research notes.*
