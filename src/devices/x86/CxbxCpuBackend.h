// Versioned C ABI between Cxbx and its out-of-process-build CPU backend.
//
// The implementation is expected to be a packaged QEMU/TCG DLL.  Keeping
// QEMU types out of this header lets the Cxbx core remain buildable with MSVC
// while QEMU is built with its supported MSYS2 toolchain.
#pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
# define QEMU_CXBX_CPU_CALL __cdecl
#else
# define QEMU_CXBX_CPU_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define QEMU_CXBX_CPU_ABI_VERSION UINT32_C(0x00010002)
#define QEMU_CXBX_CPU_ABI_MAJOR(version) ((uint32_t)(version) >> 16)

// Synthetic Xbox kernel addresses intercepted by the TCG backend before an
// instruction fetch.  The 0x90000000-0xAFFFFFFF gap is not part of any Xbox
// RAM, system-memory, tiled-memory, MMIO or flash range reserved by Cxbx.
// Keep each namespace in its own 64 KiB block so an address can be decoded
// without consulting host pointers.
#define QEMU_CXBX_KERNEL_GATEWAY_BASE UINT32_C(0xA0000000)
#define QEMU_CXBX_XBDM_GATEWAY_BASE UINT32_C(0xA0010000)
#define QEMU_CXBX_XDK_GATEWAY_BASE UINT32_C(0xA0020000)
#define QEMU_CXBX_THREAD_RETURN_GATEWAY UINT32_C(0xA003FFF0)
#define QEMU_CXBX_GATEWAY_STRIDE UINT32_C(16)

// Kernel data exports are mapped one host page per ordinal.  Function
// gateways must never overlap this range.
#define QEMU_CXBX_KERNEL_DATA_BASE UINT32_C(0xA0100000)
#define QEMU_CXBX_KERNEL_DATA_STRIDE UINT32_C(0x1000)
#define QEMU_CXBX_KERNEL_ORDINAL_COUNT UINT32_C(379)

typedef struct QemuCxbxCpu QemuCxbxCpu;

typedef enum QemuCxbxCpuResult {
	QEMU_CXBX_CPU_OK = 0,
	QEMU_CXBX_CPU_INVALID_ARGUMENT = -1,
	QEMU_CXBX_CPU_INVALID_STATE = -2,
	QEMU_CXBX_CPU_OUT_OF_MEMORY = -3,
	QEMU_CXBX_CPU_UNSUPPORTED = -4,
	QEMU_CXBX_CPU_GUEST_FAULT = -5,
	QEMU_CXBX_CPU_HOST_ERROR = -6,
} QemuCxbxCpuResult;

typedef enum QemuCxbxCpuRunReason {
	QEMU_CXBX_CPU_RUN_STOPPED = 0,
	QEMU_CXBX_CPU_RUN_HALT,
	QEMU_CXBX_CPU_RUN_GUEST_RETURN,
	QEMU_CXBX_CPU_RUN_GUEST_EXCEPTION,
	QEMU_CXBX_CPU_RUN_HOST_REQUEST,
	QEMU_CXBX_CPU_RUN_UNHANDLED_HLE,
	// The deterministic icount budget expired; registers contain the resume point.
	QEMU_CXBX_CPU_RUN_TIMESLICE,
	// A guest interrupt boundary was reached independently of host preemption.
	QEMU_CXBX_CPU_RUN_INTERRUPT,
} QemuCxbxCpuRunReason;

typedef enum QemuCxbxCpuInterruptFlags {
	QEMU_CXBX_CPU_INTERRUPT_HARD = 1u << 0,
	QEMU_CXBX_CPU_INTERRUPT_NMI = 1u << 1,
} QemuCxbxCpuInterruptFlags;

typedef enum QemuCxbxCpuMemoryFlags {
	QEMU_CXBX_CPU_MEMORY_READ = 1u << 0,
	QEMU_CXBX_CPU_MEMORY_WRITE = 1u << 1,
	QEMU_CXBX_CPU_MEMORY_EXECUTE = 1u << 2,
	// host_address points at storage owned by Cxbx. QEMU must never free it.
	QEMU_CXBX_CPU_MEMORY_HOST_POINTER = 1u << 3,
} QemuCxbxCpuMemoryFlags;

typedef struct QemuCxbxCpuRegisters {
	uint32_t struct_size;
	uint32_t version;
	uint32_t eax;
	uint32_t ecx;
	uint32_t edx;
	uint32_t ebx;
	uint32_t esp;
	uint32_t ebp;
	uint32_t esi;
	uint32_t edi;
	uint32_t eip;
	uint32_t eflags;
	uint16_t cs;
	uint16_t ds;
	uint16_t es;
	uint16_t fs;
	uint16_t gs;
	uint16_t ss;
	uint32_t cs_base;
	uint32_t ds_base;
	uint32_t es_base;
	uint32_t fs_base;
	uint32_t gs_base;
	uint32_t ss_base;
} QemuCxbxCpuRegisters;

#define QEMU_CXBX_CPU_REGISTERS_VERSION 1u

typedef struct QemuCxbxCpuRunResult {
	uint32_t struct_size;
	uint32_t version;
	QemuCxbxCpuRunReason reason;
	uint32_t exception_vector;
	uint32_t error_code;
	uint32_t fault_address;
} QemuCxbxCpuRunResult;

#define QEMU_CXBX_CPU_RUN_RESULT_VERSION 1u

typedef int (QEMU_CXBX_CPU_CALL *QemuCxbxCpuGuestRead)(
	void* memory_opaque, uint32_t guest_address, void* buffer, size_t size);
typedef int (QEMU_CXBX_CPU_CALL *QemuCxbxCpuGuestWrite)(
	void* memory_opaque, uint32_t guest_address, const void* buffer, size_t size);

typedef struct QemuCxbxCpuHleCall {
	uint32_t struct_size;
	uint32_t version;
	// Kernel calls use their Xbox ordinal. Patched XDK calls use an ID in a
	// separate namespace selected by gateway_kind.
	uint32_t gateway_kind;
	uint32_t gateway_id;
	QemuCxbxCpuRegisters* registers;
	void* memory_opaque;
	QemuCxbxCpuGuestRead read_guest;
	QemuCxbxCpuGuestWrite write_guest;
} QemuCxbxCpuHleCall;

#define QEMU_CXBX_CPU_HLE_CALL_VERSION 1u
#define QEMU_CXBX_GATEWAY_KERNEL 1u
#define QEMU_CXBX_GATEWAY_XDK 2u
#define QEMU_CXBX_GATEWAY_THREAD_RETURN 3u

// Return QEMU_CXBX_CPU_OK after updating registers and ESP. Any other value
// stops the vCPU and is reported as QEMU_CXBX_CPU_RUN_UNHANDLED_HLE.
typedef int (QEMU_CXBX_CPU_CALL *QemuCxbxCpuHleCallback)(
	void* opaque, QemuCxbxCpuHleCall* call);
typedef uint32_t (QEMU_CXBX_CPU_CALL *QemuCxbxCpuIoReadCallback)(
	void* opaque, uint16_t port, uint32_t size);
typedef void (QEMU_CXBX_CPU_CALL *QemuCxbxCpuIoWriteCallback)(
	void* opaque, uint16_t port, uint32_t value, uint32_t size);
typedef uint32_t (QEMU_CXBX_CPU_CALL *QemuCxbxCpuMmioReadCallback)(
	void* opaque, uint32_t address, uint32_t size);
typedef void (QEMU_CXBX_CPU_CALL *QemuCxbxCpuMmioWriteCallback)(
	void* opaque, uint32_t address, uint32_t value, uint32_t size);
typedef void (QEMU_CXBX_CPU_CALL *QemuCxbxCpuLogCallback)(
	void* opaque, uint32_t level, const char* message_utf8);

typedef struct QemuCxbxCpuConfig {
	uint32_t struct_size;
	uint32_t version;
	void* opaque;
	QemuCxbxCpuHleCallback hle;
	QemuCxbxCpuIoReadCallback io_read;
	QemuCxbxCpuIoWriteCallback io_write;
	QemuCxbxCpuMmioReadCallback mmio_read;
	QemuCxbxCpuMmioWriteCallback mmio_write;
	QemuCxbxCpuLogCallback log;
} QemuCxbxCpuConfig;

#define QEMU_CXBX_CPU_CONFIG_VERSION 1u

typedef uint32_t (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_get_api_version_fn)(void);
typedef int (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_create_fn)(
	const QemuCxbxCpuConfig* config, QemuCxbxCpu** cpu_out);
typedef void (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_destroy_fn)(QemuCxbxCpu* cpu);
typedef int (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_map_memory_fn)(
	QemuCxbxCpu* cpu, uint32_t guest_address, uint64_t size,
	void* host_address, uint32_t flags);
typedef int (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_unmap_memory_fn)(
	QemuCxbxCpu* cpu, uint32_t guest_address, uint64_t size);
typedef int (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_guest_commit_fn)(
	QemuCxbxCpu* cpu, uint32_t guest_address, uint64_t size,
	void* host_address, uint32_t flags);
typedef int (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_guest_protect_fn)(
	QemuCxbxCpu* cpu, uint32_t guest_address, uint64_t size, uint32_t flags);
typedef int (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_guest_decommit_fn)(
	QemuCxbxCpu* cpu, uint32_t guest_address, uint64_t size);
typedef int (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_set_registers_fn)(
	QemuCxbxCpu* cpu, const QemuCxbxCpuRegisters* registers);
typedef int (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_get_registers_fn)(
	QemuCxbxCpu* cpu, QemuCxbxCpuRegisters* registers);
typedef int (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_run_fn)(
	QemuCxbxCpu* cpu, QemuCxbxCpuRunResult* result);
typedef int (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_interrupt_fn)(
	QemuCxbxCpu* cpu, uint32_t interrupt_flags);
typedef void (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_request_stop_fn)(QemuCxbxCpu* cpu);
typedef void (QEMU_CXBX_CPU_CALL *qemu_cxbx_cpu_flush_fn)(
	QemuCxbxCpu* cpu, uint32_t guest_address, uint64_t size);

#ifdef __cplusplus
}
#endif
