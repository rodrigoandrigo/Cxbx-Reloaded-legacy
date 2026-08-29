# UWP x64 executor boundary

The UWP package has exactly two configurations: Debug x64 and Release x64.
It does not launch `cxbxr-ldr.exe`, load `cxbxr-emu.dll` as a child, exchange
window messages, or create the desktop `EmuShared` file mapping.

## Completed host contract

`CxbxUwpEmulatorSession` implements the in-process lifecycle:

- `Start`, `Pause`, `Resume`, `Stop` and explicit session states;
- brokered game/data/log paths through `CxbxUwpBootConfig`;
- callback notifications without a console or HWND;
- ABI-versioned registration through `CxbxUwpCoreExecutor`;
- validation that `Backend_D3D11` has a registered `SwapChainPanel` surface.

The provider's `boot` entry point must start its virtual CPU worker and return;
it must not occupy the XAML/UI thread. Pause, resume and stop are synchronous
control operations and must not wait indefinitely.

`EmuShared::Init` also has a UWP path that allocates process-local state instead
of a named file mapping, and the UWP IPC functions are local no-ops. They remain
available temporarily to reduce churn while subsystems move to direct settings
and session callbacks.

## Implemented CPU provider

The legacy core is not a conventional portable Xbox CPU emulator. Guest x86
instructions execute natively in its 32-bit host process. HLE patches use x86
calling conventions, inline assembly and naked functions, while guest pointers
are intentionally 32-bit.

An x64 process cannot execute that guest code directly. The UWP target now uses
the pinned `lib86cpu` dynamic recompiler and implements the following:

1. a headless Store static-library build with no desktop debugger/UI stack;
2. `VirtualAllocFromApp` JIT allocation and App-family memory-map wrappers;
3. a real instruction self-test before accepting a title;
4. strict XBE header/section validation and 64 MiB guest-RAM mapping;
5. retail/debug entry-point decoding and asynchronous CPU execution;
6. synchronous pause, resume and stop through the lifecycle ABI;
7. all executor and recompiler logs appended to the brokered LocalFolder log.
8. per-ordinal kernel stubs generated without executable desktop DLLs;
9. correct x86 `stdcall`, `cdecl` and `fastcall` return/stack handling for the
   implemented exports;
10. guest-side data locations for the imported kernel variables.

The picker intentionally accepts `.xbe` only. ISO/CCI filesystem mounting is a
separate media-layer concern and is not represented as a raw executable.

## NT services implemented in the dispatcher

`UwpKernelBridge` now owns the first complete UWP-safe NT service layer used by
the executor:

- private 32-bit guest handles with close/duplicate/reference operations;
- `NtCreateFile`, `NtOpenFile`, read, write, flush, delete, position/EOF and
  common file-information queries;
- Xbox `D:`/`CdRom0` names normalized below the authorized original game
  folder, while writable partitions/drives remain below `dataRoot`; `..`,
  invalid components and root escapes are rejected before an OS call;
- file/directory access only through App-family APIs (`CreateFile2FromAppW`,
  `CreateDirectoryFromAppW` and `DeleteFileFromAppW`);
- in-memory Executive/NT events, mutants, semaphores and timers;
- single and multiple waits, delay, yield, priority metadata and an interruptible
  wait path so `Stop` cannot hang behind an infinite guest wait;
- basic `ObCreateObject`, insert/open/reference/dereference services and the
  corresponding kernel object-type data exports.

## Multithread, APC and device expansion

The x64 executor now runs `lib86cpu` in 2 ms slices and the kernel bridge owns a
guest scheduler above the single emulated Xbox processor. `PsCreateSystemThread`
and `PsCreateSystemThreadEx` create independent x86 register contexts, kernel
stacks, KTHREAD objects and per-thread TIB/TLS blocks. Runnable, sleeping,
waiting, suspended and terminated states participate in round-robin scheduling;
thread handles become signaled on exit, and waits/delays yield the virtual CPU
instead of blocking other guest threads.

`KeInitializeApc`, `KeInsertQueueApc` and `NtQueueApcThread` populate per-thread
queues. Kernel/normal APC work is injected at a scheduling boundary, while user
APCs wait for an alertable wait and resume it with `STATUS_USER_APC`. I/O
completion events and APC callbacks are also connected to the synchronous UWP
file/control path.

`KeInitializeDpc`, `KeInsertQueueDpc` and `KeRemoveQueueDpc` maintain the Xbox
`KDPC` insertion state and execute deferred routines at `DISPATCH_LEVEL` without
allowing a scheduler switch inside the callback. One-shot and periodic timers
queue their configured DPC with the system-time arguments. Software interrupt
requests are latched until IRQL permits delivery.

`KeInitializeInterrupt`, connect/disconnect, HAL enable/disable/vector services
and `KeSynchronizeExecution` preserve the guest `KINTERRUPT` layout and IRQL
transitions. `UwpDeviceInterrupts.h` exposes a dependency-light, thread-safe
producer ABI for GPU (IRQ 3), USB (1/9), network (4), APU/codec (5/6) and IDE
(14). Edge completions are coalesced, while level sources retain individual
source bits until the producer acknowledges them. State asserted before an ISR
is connected is retained; the highest eligible IRQL is injected first and
service counts are updated after the guest ISR returns. A successful D3D11
swap-chain presentation now produces the real GPU/VBlank edge. The UWP package
does not synthesize audio or USB interrupts while those device backends are not
compiled into it.

`NtQueryDirectoryFile` maintains a search cursor per directory handle, supports
restart and Xbox ANSI masks, omits `.`/`..`, and writes the 32-bit
`FILE_DIRECTORY_INFORMATION` layout. Device controls currently cover Xbox DVD
authentication, CD-ROM TOC/geometry, disk geometry, partition/length/writable
state, storage verification/device-number/hotplug queries; filesystem controls
cover lock/unlock/dismount/mounted/dirty/compression queries and FATX metadata
read/write against the brokered file handle. Unknown title-specific control codes return
`STATUS_INVALID_DEVICE_REQUEST` without escaping the UWP capability boundary.
They also produce rate-limited JSON-line diagnostics containing XBE Title ID,
decoded CTL device/function/method/access fields, target class, buffer sizes and
the first 16 input bytes. This makes per-title controls reproducible from the
normal LocalFolder log without recording host paths or guessing a successful
response.

At boot, the XBE TLS directory is validated, its raw and zero-fill data are
copied to guest RAM, TLS index zero is published, and a 32-bit TIB/TLS vector is
installed as the hidden FS base. Raised Executive/RTL exceptions are translated
to 32-bit `EXCEPTION_RECORD`/`CONTEXT` data and delivered to the first valid
guest SEH registration. A handler returning `ExceptionContinueExecution`
restores the saved CPU context; absent or rejecting handlers stop the virtual
CPU deterministically without raising native x64 SEH across the UWP ABI.

Imported but unsupported ordinals remain hooked: they log
`STATUS_NOT_IMPLEMENTED` and stop deterministically instead of returning with an
unknown stack layout. Remaining compatibility breadth is implementing the UWP
audio/USB/network device state behind the producer ABI, controls captured from
real title runs and title-specific kernel exports. The
bridge never jumps into legacy naked x86 HLE patches from the x64 process.
