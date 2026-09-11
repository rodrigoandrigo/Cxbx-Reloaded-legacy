#define LOG_PREFIX CXBXR_MODULE::X86

#include "devices/x86/EmuX86.h"

#include <atomic>
#include <cassert>
#include <array>
#include <cstring>
#include <mutex>
#include <string>
#include <tuple>
#include <type_traits>
#include <unordered_set>
#include <utility>

#include "Logging.h"
#include "common/Timer.h"
#include "core/kernel/init/CxbxKrnl.h"
#undef RtlFillMemory
#undef RtlMoveMemory
#undef RtlZeroMemory
#include "core/kernel/exports/xboxkrnl.h"
#include "core/kernel/support/Emu.h"
#include "devices/Chihiro/MediaBoard.h"
#include "devices/PCIBus.h"
#include "devices/Xbox.h"
#include "devices/x86/CxbxCpuBackendLoader.h"

extern uint32_t GetAPUTime();
extern std::atomic_bool g_bEnableAllInterrupts;

namespace {
int g_fieldPin = 0;
std::mutex g_tcgMappingMutex;
// QEMU owns one process-wide TCG/system-memory context.  Xbox threads are
// represented by separate CPU register contexts, but backend operations must
// still be serialized to preserve the single physical Xbox CPU semantics and
// to avoid racing CPU realization with memory-region transactions.
std::mutex g_tcgBackendMutex;
std::unordered_set<uint64_t> g_tcgMappings;
QemuCxbxCpu* g_tcgMappingCpu = nullptr;
std::unordered_set<QemuCxbxCpu*> g_tcgCpus;
bool g_tcgInitialMemoryImported = false;

uint32_t TcgMemoryFlags(DWORD protection)
{
	uint32_t flags = QEMU_CXBX_CPU_MEMORY_READ |
		QEMU_CXBX_CPU_MEMORY_HOST_POINTER;
	const DWORD access = protection & 0xff;
	if (access == PAGE_READWRITE || access == PAGE_WRITECOPY ||
		access == PAGE_EXECUTE_READWRITE || access == PAGE_EXECUTE_WRITECOPY) {
		flags |= QEMU_CXBX_CPU_MEMORY_WRITE;
	}
	if (access == PAGE_EXECUTE || access == PAGE_EXECUTE_READ ||
		access == PAGE_EXECUTE_READWRITE || access == PAGE_EXECUTE_WRITECOPY) {
		flags |= QEMU_CXBX_CPU_MEMORY_EXECUTE;
	}
	return flags;
}

constexpr uint32_t AlignGuestArgument(size_t size)
{
	return static_cast<uint32_t>((size + 3) & ~size_t(3));
}

template <typename T>
T ReadGuestValue(QemuCxbxCpuHleCall* call, uint32_t address)
{
	using Value = std::remove_cv_t<std::remove_reference_t<T>>;
	Value value{};
	if (!call->read_guest(call->memory_opaque, address, &value, sizeof(value))) {
		throw std::runtime_error("TCG could not read a kernel argument");
	}
	return static_cast<T>(value);
}

template <typename Tuple, size_t Index, size_t... Previous>
constexpr uint32_t GuestTupleOffset(std::index_sequence<Previous...>)
{
	return (0u + ... + AlignGuestArgument(sizeof(std::tuple_element_t<Previous, Tuple>)));
}

template <typename Tuple, size_t Index>
constexpr uint32_t GuestTupleOffset()
{
	return GuestTupleOffset<Tuple, Index>(std::make_index_sequence<Index>{});
}

template <typename Result>
void StoreGuestResult(QemuCxbxCpuRegisters* registers, Result result)
{
	using Value = std::remove_cv_t<std::remove_reference_t<Result>>;
	if constexpr (std::is_pointer_v<Value>) {
		registers->eax = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(result));
	}
	else if constexpr (sizeof(Value) <= sizeof(uint32_t)) {
		uint32_t raw = 0;
		std::memcpy(&raw, &result, sizeof(Value));
		registers->eax = raw;
	}
	else if constexpr (sizeof(Value) <= sizeof(uint64_t)) {
		uint64_t raw = 0;
		std::memcpy(&raw, &result, sizeof(Value));
		registers->eax = static_cast<uint32_t>(raw);
		registers->edx = static_cast<uint32_t>(raw >> 32);
	}
}

bool CompleteKernelCall(QemuCxbxCpuHleCall* call, uint32_t stack_bytes)
{
	uint32_t return_address = 0;
	if (!call->read_guest(call->memory_opaque, call->registers->esp,
		&return_address, sizeof(return_address))) {
		return false;
	}
	call->registers->eip = return_address;
	call->registers->esp += sizeof(uint32_t) + stack_bytes;
	return true;
}

template <auto Function, typename Result, typename... Args, size_t... Index>
int InvokeKernelImpl(QemuCxbxCpuHleCall* call, Result (*)(Args...),
	std::index_sequence<Index...>)
{
	using Tuple = std::tuple<Args...>;
	try {
		if constexpr (std::is_void_v<Result>) {
			Function(ReadGuestValue<Args>(call, call->registers->esp + 4 +
				GuestTupleOffset<Tuple, Index>())...);
		}
		else {
			auto result = Function(ReadGuestValue<Args>(call,
				call->registers->esp + 4 + GuestTupleOffset<Tuple, Index>())...);
			StoreGuestResult(call->registers, result);
		}
	}
	catch (...) {
		return QEMU_CXBX_CPU_HOST_ERROR;
	}
	constexpr uint32_t bytes = (0u + ... + AlignGuestArgument(sizeof(Args)));
	return CompleteKernelCall(call, bytes) ? QEMU_CXBX_CPU_OK : QEMU_CXBX_CPU_GUEST_FAULT;
}

template <auto Function, typename Result, typename... Args>
int InvokeKernelTyped(QemuCxbxCpuHleCall* call, Result (*signature)(Args...))
{
	return InvokeKernelImpl<Function>(call, signature,
		std::index_sequence_for<Args...>{});
}

template <auto Function>
int InvokeKernel(QemuCxbxCpuHleCall* call)
{
	return InvokeKernelTyped<Function>(call, Function);
}

template <typename T>
T RegisterArgument(uint32_t value)
{
	using Value = std::remove_cv_t<std::remove_reference_t<T>>;
	if constexpr (std::is_pointer_v<Value>) {
		return reinterpret_cast<Value>(static_cast<uintptr_t>(value));
	}
	else {
		Value result{};
		std::memcpy(&result, &value, (std::min)(sizeof(result), sizeof(value)));
		return result;
	}
}

template <auto Function, typename Result, typename First, typename Second,
	typename... Rest, size_t... Index>
int InvokeKernelFastImpl(QemuCxbxCpuHleCall* call,
	Result (*)(First, Second, Rest...), std::index_sequence<Index...>)
{
	using RestTuple = std::tuple<Rest...>;
	if constexpr (std::is_void_v<Result>) {
		Function(RegisterArgument<First>(call->registers->ecx),
			RegisterArgument<Second>(call->registers->edx),
			ReadGuestValue<Rest>(call, call->registers->esp + 4 +
				GuestTupleOffset<RestTuple, Index>())...);
	}
	else {
		auto result = Function(RegisterArgument<First>(call->registers->ecx),
			RegisterArgument<Second>(call->registers->edx),
			ReadGuestValue<Rest>(call, call->registers->esp + 4 +
				GuestTupleOffset<RestTuple, Index>())...);
		StoreGuestResult(call->registers, result);
	}
	constexpr uint32_t bytes = (0u + ... + AlignGuestArgument(sizeof(Rest)));
	return CompleteKernelCall(call, bytes) ? QEMU_CXBX_CPU_OK : QEMU_CXBX_CPU_GUEST_FAULT;
}

template <auto Function, typename Result, typename First, typename Second,
	typename... Rest>
int InvokeKernelFastTyped(QemuCxbxCpuHleCall* call,
	Result (*signature)(First, Second, Rest...))
{
	return InvokeKernelFastImpl<Function>(call, signature,
		std::index_sequence_for<Rest...>{});
}

template <auto Function, typename Result, typename First>
int InvokeKernelFastTyped(QemuCxbxCpuHleCall* call, Result (*)(First))
{
	try {
		if constexpr (std::is_void_v<Result>) {
			Function(RegisterArgument<First>(call->registers->ecx));
		}
		else {
			auto result = Function(RegisterArgument<First>(call->registers->ecx));
			StoreGuestResult(call->registers, result);
		}
	}
	catch (...) {
		return QEMU_CXBX_CPU_HOST_ERROR;
	}
	return CompleteKernelCall(call, 0) ? QEMU_CXBX_CPU_OK : QEMU_CXBX_CPU_GUEST_FAULT;
}

template <auto Function, typename Result>
int InvokeKernelFastTyped(QemuCxbxCpuHleCall* call, Result (*)())
{
	try {
		if constexpr (std::is_void_v<Result>) {
			Function();
		}
		else {
			auto result = Function();
			StoreGuestResult(call->registers, result);
		}
	}
	catch (...) {
		return QEMU_CXBX_CPU_HOST_ERROR;
	}
	return CompleteKernelCall(call, 0) ? QEMU_CXBX_CPU_OK : QEMU_CXBX_CPU_GUEST_FAULT;
}

template <auto Function>
int InvokeKernelFast(QemuCxbxCpuHleCall* call)
{
	return InvokeKernelFastTyped<Function>(call, Function);
}

int InvokeKernelVarargs(QemuCxbxCpuHleCall*)
{
	// Vararg formatting requires an x86 va_list translator. Keep the gateway
	// explicit so it cannot accidentally be invoked with the host x64 ABI.
	return QEMU_CXBX_CPU_UNSUPPORTED;
}

int DispatchKernelGateway(QemuCxbxCpuHleCall* call)
{
	switch (call->gateway_id) {
#include "devices/x86/CxbxKernelDispatch.inc"
	default:
		return QEMU_CXBX_CPU_UNSUPPORTED;
	}
}

int QEMU_CXBX_CPU_CALL TcgHleCallback(void*, QemuCxbxCpuHleCall* call)
{
	if (!call || call->version != QEMU_CXBX_CPU_HLE_CALL_VERSION) {
		return QEMU_CXBX_CPU_INVALID_ARGUMENT;
	}
	if (call->gateway_kind == QEMU_CXBX_GATEWAY_KERNEL) {
		EmuLogInit(LOG_LEVEL::INFO, "TCG HLE kernel enter (ordinal=%u eip=0x%08X)",
			call->gateway_id, call->registers ? call->registers->eip : 0);
		const int result = DispatchKernelGateway(call);
		EmuLogInit(LOG_LEVEL::INFO, "TCG HLE kernel exit (ordinal=%u status=%d eip=0x%08X)",
			call->gateway_id, result, call->registers ? call->registers->eip : 0);
		return result;
	}
	return QEMU_CXBX_CPU_UNSUPPORTED;
}

uint32_t QEMU_CXBX_CPU_CALL TcgIoRead(void*, uint16_t port, uint32_t size)
{
	return EmuX86_IORead(port, static_cast<int>(size));
}

void QEMU_CXBX_CPU_CALL TcgIoWrite(void*, uint16_t port, uint32_t value, uint32_t size)
{
	EmuX86_IOWrite(port, value, static_cast<int>(size));
}

uint32_t QEMU_CXBX_CPU_CALL TcgMmioRead(void*, uint32_t address, uint32_t size)
{
	return EmuX86_Read(address, static_cast<int>(size));
}

void QEMU_CXBX_CPU_CALL TcgMmioWrite(void*, uint32_t address, uint32_t value,
	uint32_t size)
{
	EmuX86_Write(address, value, static_cast<int>(size));
}

void QEMU_CXBX_CPU_CALL TcgLog(void*, uint32_t level, const char* message)
{
	EmuLog(level >= 3 ? LOG_LEVEL::WARNING : LOG_LEVEL::DEBUG, "TCG: %s", message);
}

bool MapCommittedRange(QemuCxbxCpu* cpu, uint32_t first, uint32_t last)
{
	const auto* backend = CxbxCpuBackendGetExports();
	uintptr_t cursor = first;
	while (cursor <= last) {
		MEMORY_BASIC_INFORMATION info{};
		if (!VirtualQuery(reinterpret_cast<void*>(cursor), &info, sizeof(info))) {
			return false;
		}
		const uintptr_t base = reinterpret_cast<uintptr_t>(info.BaseAddress);
		const uintptr_t end = (std::min)(base + info.RegionSize,
			static_cast<uintptr_t>(last) + 1);
		if (info.State == MEM_COMMIT && !(info.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
			const uint64_t key = (static_cast<uint64_t>(base) << 32) |
				static_cast<uint32_t>(end - base);
			if (g_tcgMappings.insert(key).second) {
				const int result = backend->map_memory(cpu, static_cast<uint32_t>(base),
					end - base, reinterpret_cast<void*>(base),
					QEMU_CXBX_CPU_MEMORY_READ | QEMU_CXBX_CPU_MEMORY_WRITE |
					QEMU_CXBX_CPU_MEMORY_EXECUTE | QEMU_CXBX_CPU_MEMORY_HOST_POINTER);
				if (result != QEMU_CXBX_CPU_OK) {
					g_tcgMappings.erase(key);
					return false;
				}
			}
		}
		if (end <= cursor) {
			break;
		}
		cursor = end;
	}
	return true;
}

bool MapGuestMemory(QemuCxbxCpu* cpu)
{
	static constexpr std::array<std::pair<uint32_t, uint32_t>, 7> ranges{{
		{ 0x00010000u, 0x7FFEFFFFu }, { 0x80000000u, 0x8FFFFFFFu },
		{ 0xB0000000u, 0xBFFFFFFFu }, { 0xC0000000u, 0xC03FFFFFu },
		{ 0xD0000000u, 0xEFFFFFFFu }, { 0xF0000000u, 0xF3FFFFFFu },
		{ 0xF8000000u, 0xFFBFFFFFu },
	}};
	std::lock_guard backendLock(g_tcgBackendMutex);
	std::lock_guard mappingLock(g_tcgMappingMutex);
	if (g_tcgInitialMemoryImported) {
		return true;
	}
	for (const auto& range : ranges) {
		if (!MapCommittedRange(cpu, range.first, range.second)) {
			return false;
		}
	}
	for (uint32_t ordinal = 0; ordinal < QEMU_CXBX_KERNEL_ORDINAL_COUNT; ++ordinal) {
		if (!CxbxKrnl_KernelThunkIsData(ordinal)) {
			continue;
		}
		const uintptr_t host_page = CxbxKrnl_KernelThunkTable[ordinal] & ~uintptr_t(0xFFF);
		const uint64_t key = (uint64_t(QEMU_CXBX_KERNEL_DATA_BASE +
			ordinal * QEMU_CXBX_KERNEL_DATA_STRIDE) << 32) | 0x1000u;
		if (g_tcgMappings.insert(key).second && CxbxCpuBackendGetExports()->map_memory(
			cpu, QEMU_CXBX_KERNEL_DATA_BASE + ordinal * QEMU_CXBX_KERNEL_DATA_STRIDE,
			0x1000, reinterpret_cast<void*>(host_page),
			QEMU_CXBX_CPU_MEMORY_READ | QEMU_CXBX_CPU_MEMORY_WRITE |
			QEMU_CXBX_CPU_MEMORY_HOST_POINTER) != QEMU_CXBX_CPU_OK) {
			g_tcgMappings.erase(key);
			return false;
		}
	}
	g_tcgInitialMemoryImported = true;
	return true;
}

int CreateTcgCpu(const QemuCxbxCpuConfig* config, QemuCxbxCpu** cpu)
{
	std::lock_guard lock(g_tcgBackendMutex);
	return CxbxCpuBackendGetExports()->create(config, cpu);
}

int SetTcgRegisters(QemuCxbxCpu* cpu, const QemuCxbxCpuRegisters* registers)
{
	std::lock_guard lock(g_tcgBackendMutex);
	return CxbxCpuBackendGetExports()->set_registers(cpu, registers);
}

int RunTcgCpu(QemuCxbxCpu* cpu, QemuCxbxCpuRunResult* result)
{
	// run() is fairly serialized by the backend's round-robin ticket queue.
	// Keeping the outer mutex here would hide waiters from that queue and allow
	// the current thread to starve a newly-created Xbox thread.
	return CxbxCpuBackendGetExports()->run(cpu, result);
}

int GetTcgRegisters(QemuCxbxCpu* cpu, QemuCxbxCpuRegisters* registers)
{
	std::lock_guard lock(g_tcgBackendMutex);
	return CxbxCpuBackendGetExports()->get_registers(cpu, registers);
}

void DestroyTcgCpu(QemuCxbxCpu* cpu)
{
	std::lock_guard lock(g_tcgBackendMutex);
	CxbxCpuBackendGetExports()->destroy(cpu);
}

uint32_t ReadFlash(uint32_t address)
{
	switch (address) {
	case 0x08:
		return 0x2B16D065;
	case 0x78:
		return 0x90;
	default:
		EmuLog(LOG_LEVEL::WARNING, "Read FLASH_ROM (0x%.8X) [unknown address]", address);
		return UINT32_MAX;
	}
}
}

void EmuX86_GuestCommit(uint32_t address, size_t size, void* host_pointer,
	DWORD protection)
{
	if (!size || !host_pointer) return;
	std::lock_guard backendLock(g_tcgBackendMutex);
	std::lock_guard mappingLock(g_tcgMappingMutex);
	if (!g_tcgMappingCpu) return;
	const uint64_t key = (uint64_t(address) << 32) | static_cast<uint32_t>(size);
	if (!g_tcgMappings.insert(key).second) return;
	if (CxbxCpuBackendGetExports()->guest_commit(g_tcgMappingCpu, address, size,
		host_pointer, TcgMemoryFlags(protection)) != QEMU_CXBX_CPU_OK) {
		g_tcgMappings.erase(key);
	}
}

void EmuX86_GuestProtect(uint32_t address, size_t size, DWORD protection)
{
	if (!size) return;
	std::lock_guard backendLock(g_tcgBackendMutex);
	if (g_tcgMappingCpu) {
		CxbxCpuBackendGetExports()->guest_protect(g_tcgMappingCpu, address, size,
			TcgMemoryFlags(protection));
	}
}

void EmuX86_GuestDecommit(uint32_t address, size_t size)
{
	if (!size) return;
	std::lock_guard backendLock(g_tcgBackendMutex);
	std::lock_guard mappingLock(g_tcgMappingMutex);
	if (!g_tcgMappingCpu) return;
	const uint64_t key = (uint64_t(address) << 32) | static_cast<uint32_t>(size);
	if (CxbxCpuBackendGetExports()->guest_decommit(g_tcgMappingCpu, address,
		size) == QEMU_CXBX_CPU_OK) {
		g_tcgMappings.erase(key);
	}
}

uint32_t EmuX86_IORead(xbox::addr_xt addr, int size)
{
	if (g_bIsChihiro && addr >= 0x4000 && addr <= 0x40ff) {
		return g_MediaBoard->LpcRead(addr, size);
	}

	switch (addr) {
	case 0x8008:
		if (size == sizeof(uint32_t)) {
			return static_cast<uint32_t>(Timer_GetScaledPerformanceCounter(3579545));
		}
		break;
	case 0x80c0:
		if (size == sizeof(uint8_t)) {
			g_fieldPin = (g_fieldPin + 1) & 1;
			return static_cast<uint32_t>(g_fieldPin << 5);
		}
		break;
	default:
		break;
	}

	uint32_t value = 0;
	if (g_PCIBus && g_PCIBus->IORead(addr, &value, size)) {
		return value;
	}
	EmuLog(LOG_LEVEL::WARNING, "TCG IO read 0x%04X/%d [unhandled]", addr, size);
	return 0;
}

void EmuX86_IOWrite(xbox::addr_xt addr, uint32_t value, int size)
{
	if (g_bIsChihiro && addr >= 0x4000 && addr <= 0x40ff) {
		g_MediaBoard->LpcWrite(addr, value, size);
		return;
	}
	if (g_PCIBus && g_PCIBus->IOWrite(addr, value, size)) {
		return;
	}
	EmuLog(LOG_LEVEL::WARNING, "TCG IO write 0x%04X = 0x%08X/%d [unhandled]",
		addr, value, size);
}

uint32_t EmuX86_Read(xbox::addr_xt addr, int size)
{
	if (size != 1 && size != 2 && size != 4) {
		EmuLog(LOG_LEVEL::WARNING, "TCG MMIO read 0x%08X has invalid size %d", addr, size);
		return 0;
	}
	if ((addr & static_cast<xbox::addr_xt>(size - 1)) != 0) {
		EmuLog(LOG_LEVEL::WARNING, "TCG MMIO read 0x%08X/%d is unaligned", addr, size);
	}
	if (addr >= FLASH_DEVICE1_BASE) {
		return ReadFlash((addr - FLASH_DEVICE1_BASE) % KiB(256));
	}
	if (addr == 0xfe80200c) {
		return GetAPUTime();
	}

	uint32_t value = 0;
	if (g_PCIBus && g_PCIBus->MMIORead(addr, &value, size)) {
		return value;
	}
	EmuLog(LOG_LEVEL::WARNING, "TCG MMIO read 0x%08X/%d [unhandled]", addr, size);
	return 0;
}

void EmuX86_Write(xbox::addr_xt addr, uint32_t value, int size)
{
	if (size != 1 && size != 2 && size != 4) {
		EmuLog(LOG_LEVEL::WARNING, "TCG MMIO write 0x%08X has invalid size %d", addr, size);
		return;
	}
	if ((addr & static_cast<xbox::addr_xt>(size - 1)) != 0) {
		EmuLog(LOG_LEVEL::WARNING, "TCG MMIO write 0x%08X/%d is unaligned", addr, size);
	}
	if (addr >= FLASH_DEVICE1_BASE) {
		EmuLog(LOG_LEVEL::WARNING, "TCG write to FLASH_ROM 0x%08X ignored", addr);
		return;
	}
	if (g_PCIBus && g_PCIBus->MMIOWrite(addr, value, size)) {
		return;
	}
	EmuLog(LOG_LEVEL::WARNING, "TCG MMIO write 0x%08X = 0x%08X/%d [unhandled]",
		addr, value, size);
}

int EmuX86_OpcodeSize(uint8_t*)
{
	// Native exception decoding is not part of the TCG execution path. Keep a
	// conservative value for legacy host-only error recovery code.
	return 1;
}

bool EmuX86_DecodeException(LPEXCEPTION_POINTERS)
{
	return false;
}

void EmuX86_Init()
{
	std::string error;
	if (!CxbxCpuBackendInitialize(error)) {
		CxbxrAbort("Unable to initialize the x86 TCG backend: %s", error.c_str());
	}
	EmuLog(LOG_LEVEL::INFO, "Using packaged QEMU/TCG i386 backend");
}

bool EmuX86_RunThread(uint32_t system_routine, uint32_t start_routine,
	uint32_t start_context, uint32_t stack_pointer, uint32_t fs_base,
	uint32_t* exception_vector)
{
	const auto* backend = CxbxCpuBackendGetExports();
	if (!backend) {
		EmuLog(LOG_LEVEL::ERROR2, "TCG backend exports unavailable");
		return false;
	}

	QemuCxbxCpuConfig config{};
	config.struct_size = sizeof(config);
	config.version = QEMU_CXBX_CPU_CONFIG_VERSION;
	config.hle = TcgHleCallback;
	config.io_read = TcgIoRead;
	config.io_write = TcgIoWrite;
	config.mmio_read = TcgMmioRead;
	config.mmio_write = TcgMmioWrite;
	config.log = TcgLog;

QemuCxbxCpu* cpu = nullptr;
	if (CreateTcgCpu(&config, &cpu) != QEMU_CXBX_CPU_OK || !cpu) {
		EmuLog(LOG_LEVEL::ERROR2, "TCG CPU creation failed (start=0x%08X)", start_routine);
		return false;
	}
	g_tcgMappingMutex.lock();
	g_tcgCpus.insert(cpu);
	g_tcgMappingCpu = cpu;
	g_tcgMappingMutex.unlock();

	bool success = false;
		do {
		// Xbox XAPI inspects the kernel PE header while creating title threads.
		// Keep this invariant intact even if guest code touched the physical page
		// after the initial kernel bootstrap.
		CxbxrKrnlEnsureDummyHeader();
		if (!MapGuestMemory(cpu)) {
			EmuLog(LOG_LEVEL::ERROR2, "TCG guest memory mapping failed (start=0x%08X)", start_routine);
			break;
		}

		const bool invoke_system_routine = system_routine != 0;
		const uint32_t argument_count = invoke_system_routine ? 2u : 1u;
		uint32_t esp = (stack_pointer - 4u * (argument_count + 1u)) & ~uint32_t(3);
		auto* stack = reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(esp));
		stack[0] = QEMU_CXBX_THREAD_RETURN_GATEWAY;
		stack[1] = invoke_system_routine ? start_routine : start_context;
		if (invoke_system_routine) {
			stack[2] = start_context;
		}

		QemuCxbxCpuRegisters registers{};
		registers.struct_size = sizeof(registers);
		registers.version = QEMU_CXBX_CPU_REGISTERS_VERSION;
		registers.eip = invoke_system_routine ? system_routine : start_routine;
		registers.esp = esp;
		registers.ebp = esp;
		registers.eflags = 0x202;
		registers.cs = 0x08;
		registers.ds = registers.es = registers.ss = 0x10;
		registers.fs = 0x18;
		registers.fs_base = fs_base;
		if (SetTcgRegisters(cpu, &registers) != QEMU_CXBX_CPU_OK) {
			EmuLog(LOG_LEVEL::ERROR2, "TCG register setup failed (eip=0x%08X esp=0x%08X)", registers.eip, registers.esp);
			break;
		}

		for (;;) {
			static std::atomic_uint32_t runIterationCounter{ 0 };
			const uint32_t runIteration =
				runIterationCounter.fetch_add(1, std::memory_order_relaxed) + 1;
			// VMManager publishes commit/protect/decommit changes incrementally.
			QemuCxbxCpuRunResult result{};
			result.struct_size = sizeof(result);
			result.version = QEMU_CXBX_CPU_RUN_RESULT_VERSION;
			EmuLogInit(LOG_LEVEL::DEBUG, "TCG backend run enter (iteration=%u eip=0x%08X)", runIteration, registers.eip);
			int runStatus = QEMU_CXBX_CPU_HOST_ERROR;
			__try {
				EmuLogInit(LOG_LEVEL::INFO, "TCG invoking backend (iteration=%u)", runIteration);
				runStatus = RunTcgCpu(cpu, &result);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				const auto code = GetExceptionCode();
				EmuLog(LOG_LEVEL::ERROR2, "TCG backend exception (code=0x%08X eip=0x%08X)", code, registers.eip);
				if (exception_vector) *exception_vector = code;
				break;
			}
			if (runStatus != QEMU_CXBX_CPU_OK) {
				EmuLog(LOG_LEVEL::ERROR2, "TCG backend run failed (status=%d eip=0x%08X reason=%d)",
					static_cast<int>(runStatus), registers.eip, static_cast<int>(result.reason));
				break;
			}
			if (GetTcgRegisters(cpu, &registers) != QEMU_CXBX_CPU_OK) {
				EmuLog(LOG_LEVEL::ERROR2, "TCG register readback failed after run");
				break;
			}
			EmuLogInit(LOG_LEVEL::INFO,
				"TCG backend run exit (reason=%d exception=%u error=0x%08X fault=0x%08X eip=0x%08X esp=0x%08X ebp=0x%08X)",
				static_cast<int>(result.reason), result.exception_vector,
				result.error_code, result.fault_address, registers.eip,
				registers.esp, registers.ebp);
			if (result.reason == QEMU_CXBX_CPU_RUN_STOPPED) {
				// The backend now consumes internal TCG interrupt/atomic exits.
				// STOPPED is only the boundary used to hand a synthetic gateway
				// back to this loop; resume immediately so the next run dispatches it.
				continue;
			}
			if (result.reason == QEMU_CXBX_CPU_RUN_TIMESLICE ||
				result.reason == QEMU_CXBX_CPU_RUN_INTERRUPT) {
				// A timeslice is scheduler preemption; an interrupt boundary lets
				// the round-robin queue run other ready Xbox contexts before resume.
				continue;
			}
			if (result.reason == QEMU_CXBX_CPU_RUN_GUEST_RETURN ||
				result.reason == QEMU_CXBX_CPU_RUN_HALT) {
				success = true;
			}
			else if (result.reason == QEMU_CXBX_CPU_RUN_GUEST_EXCEPTION &&
				exception_vector) {
				*exception_vector = result.exception_vector;
			}
			break;
		}
	} while (false);

	g_tcgMappingMutex.lock();
	g_tcgCpus.erase(cpu);
	g_tcgMappingCpu = g_tcgCpus.empty() ? nullptr : *g_tcgCpus.begin();
	g_tcgMappingMutex.unlock();
	DestroyTcgCpu(cpu);
	return success;
}
