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
std::unordered_set<uint64_t> g_tcgMappings;

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
		return DispatchKernelGateway(call);
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
	std::lock_guard lock(g_tcgMappingMutex);
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
	return true;
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
	if (backend->create(&config, &cpu) != QEMU_CXBX_CPU_OK || !cpu) {
		return false;
	}

	bool success = false;
	do {
		if (!MapGuestMemory(cpu)) {
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
		if (backend->set_registers(cpu, &registers) != QEMU_CXBX_CPU_OK) {
			break;
		}

		for (;;) {
			// HLE calls may commit new guest pages. Publish them before resuming TCG.
			if (!MapGuestMemory(cpu)) {
				break;
			}
			QemuCxbxCpuRunResult result{};
			result.struct_size = sizeof(result);
			result.version = QEMU_CXBX_CPU_RUN_RESULT_VERSION;
			if (backend->run(cpu, &result) != QEMU_CXBX_CPU_OK) {
				break;
			}
			if (result.reason == QEMU_CXBX_CPU_RUN_STOPPED) {
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

	backend->destroy(cpu);
	return success;
}
