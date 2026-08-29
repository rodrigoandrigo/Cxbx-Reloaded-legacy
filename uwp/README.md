# Cxbx-R UWP host

`Cxbx-R-uwp` is the UWP host for the port.  It deliberately owns the UWP
capability boundary; the emulation core must not use C++/CX or assume that an
arbitrary Win32 path is accessible.

## Storage contract

`UwpStorageBroker` accepts the brokered UWP objects:

- `StorageFolder` selected through `FolderPicker` is retained for the current
  run and registered in `FutureAccessList` under `cxbxr-game-folder`.
- A selected `StorageFile` is retained in `FutureAccessList`; its original path
  is passed to the executor and the game is never copied.
- `IRandomAccessStream` can still be materialized under
  `ApplicationData::Current->LocalFolder\\CxbxR\\BrokeredFiles` when no original
  filesystem item exists.
- Emulator-writable data and the log file live under
  `ApplicationData::Current->LocalFolder\\CxbxR`.

Selecting a folder launches its `default.xbe` in place and grants sibling asset
access. Xbox `D:` and `CdRom0` paths map to that authorized original folder;
writable partitions and drives remain below the LocalFolder data root.

When the core is linked into this host, configure it before booting an XBE by
passing `DataRoot` and `GameRoot` (converted from `Platform::String` to UTF-8)
to `CxbxrSetBrokeredDataPath` and `CxbxrSetBrokeredGamePath`. Configure
`CxbxrSetLogFilePath` with `LogPath`, then call `CxbxrSetConsoleLogging(false)`.

`CxbxrSetLogCallback` is available when the host wants to display log lines in
its own UI.  The common logger does not use a console when `CXBXR_UWP` is set.

## Build

```powershell
msbuild Cxbx-R-uwp.vcxproj /t:Build /p:Configuration=Debug /p:Platform=x64 /m:1
```

The project links only `WindowsApp.lib` and has been verified to package an
x64 MSIX. `m:1` avoids a sporadic generated-XAML object-file lock in this
legacy template.

## D3D11 and UWP UI

The tree includes the official legacy `Backend_D3D11` port. The UWP host no
longer builds or runs the Visual Studio sample cube. `Cxbx_R_uwpMain` registers
the device, immediate context and `SwapChainPanel` swap chain through the native
`CxbxUwpD3D11Surface` contract. When `CXBXR_UWP` is enabled, `HostRender.cpp`
acquires that surface instead of creating a desktop window or calling
`CreateSwapChainForHwnd`.

The XAML page now owns library selection, settings, status and log presentation.
XBE files and selected folders remain in their original locations as retained
brokered grants. The app package contains the D3D11 HLSL sources,
the port notes and dependency licenses. It requests no broad filesystem or
internet capability. It declares `codeGeneration`, which is required by the
x64 dynamic recompiler.

## Settings mapping

The Configurações tab persists its values in `ApplicationData.LocalSettings`.
Video VSync, aspect ratio and filtering are applied by the D3D11 presentation
host; audio volume and focus muting are applied by XAudio2; four physical
gamepads can be assigned to Xbox USB/XID addresses with a configurable
deadzone. PCM codec policy, the isolated NVNet cable, the retail/devkit/Chihiro
profile, the pixel-shader compatibility hack and the in-game overlay are also
connected to their native UWP backends or boot ABI. Logging keeps the fixed UWP
policy used before this settings port: all relevant modules write to the single
LocalFolder log, while only the pre-existing high-frequency repetition guards
discard instruction spam and sampled diagnostics.

Settings that depended on desktop-only facilities are intentionally represented
by their UWP policy instead of retaining invalid choices: graphics and audio
adapters are selected by Windows, writable storage is always LocalFolder,
game access is always brokered and in place, and pcap/console/HWND/process-child
options are absent. JIT, NV2A, MCPX/APU and USB/XID are mandatory parts of this
x64 port rather than optional HLE/LLE checkboxes.

## x64 CPU executor

The package incorporates a pinned `lib86cpu` submodule and builds it as a
headless UWP static library. GLFW, OpenGL and ImGui are not linked. Its memory
allocator uses `VirtualAllocFromApp`, and its Xbox inline page-table code uses
the Windows SDK's App-family wrappers for mapping and protection.

The lifecycle API is implemented in `UwpEmulatorSession` and the project is
x64-only. It removes command-line HWND/shared-memory startup from the UWP host.
`UwpLib86CpuExecutor` registers the provider, performs a real x86 JIT self-test,
validates and maps XBE headers/sections into 64 MiB of guest RAM, resolves retail
or debug entry-point encoding, and owns the worker/pause/resume/stop lifecycle.
`UwpKernelBridge` also rewrites the XBE kernel import table to per-ordinal guest
stubs, maps kernel data exports, and dispatches Executive, NT file/object,
scheduler/synchronization, TLS/exception, Memory Manager and RTL services through
typed x64 callbacks. All guest file names remain confined to the authorized
game/data roots and every wait is interruptible by the UWP session stop operation. See
`X64_EXECUTOR.md` for the exact supported boundary.

The executor time-slices guest system threads on the single Xbox vCPU, with a
separate x86 context and TLS block for every thread. Alertable APC delivery,
priority-ordered interrupts, timer and explicit DPC delivery, filesystem
directory enumeration, DVD/storage/disk IOCTLs and FATX/volume FSCTLs are
handled by the same UWP-safe dispatcher.

The D3D11 host reports successful swap-chain presentations as GPU IRQ 3 edges.
A lightweight producer contract also covers level/pulse signaling for future
USB, APU/audio, network and IDE backends without linking them to `lib86cpu`.
Unknown IOCTL/FSCTL diagnostics are tagged with the XBE Title ID and written to
the existing LocalFolder log; authorized host paths are not included.

Release and Debug packages are signed with `Cxbx-R-uwp_TemporaryKey.pfx`.
The certificate subject (`CN=rodri`) matches the manifest publisher; the key is
intended for local/development deployment and is not a Microsoft Store identity.
