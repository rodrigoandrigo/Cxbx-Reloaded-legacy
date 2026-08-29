#include "UwpEmulatorSession.h"
#include "UwpDeviceBus.h"
#include "UwpKernelBridge.h"
#include "UwpNv2aProducer.h"
#include "UwpXisoReader.h"

#include <lib86cpu.hpp>
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

static_assert(sizeof(void*) == 8, "The lib86cpu UWP executor is x64-only.");

namespace
{
	constexpr std::uint64_t XboxRamSize = 64ull * 1024 * 1024;
	constexpr std::uint32_t KernelVirtualMapBase = 0x80000000u;
	constexpr std::uint32_t KernelImageBase = 0x80010000u;
	constexpr std::uint32_t KernelImageMapSize = 0x00100000u;
	constexpr std::uint32_t PhysicalAliasMapSize = static_cast<std::uint32_t>(XboxRamSize);
	constexpr std::uint32_t KernelExportCount = 379;
	constexpr std::uint32_t XbeMagic = 0x48454258; // "XBEH"
	constexpr std::uint32_t RetailEntryXor = 0xA8FC57AB;
	constexpr std::uint32_t DebugEntryXor = 0x94859D4B;
	constexpr std::uint32_t ChihiroEntryXor = 0x40B5C16E;

#pragma pack(push, 1)
	struct XbeHeader
	{
		std::uint32_t magic;
		std::uint8_t signature[256];
		std::uint32_t baseAddress;
		std::uint32_t headerSize;
		std::uint32_t imageSize;
		std::uint32_t imageHeaderSize;
		std::uint32_t timeDate;
		std::uint32_t certificateAddress;
		std::uint32_t sectionCount;
		std::uint32_t sectionHeadersAddress;
		std::uint32_t initFlags;
		std::uint32_t encodedEntryAddress;
		std::uint32_t tlsAddress;
		std::uint32_t stackCommit;
		std::uint32_t heapReserve;
		std::uint32_t heapCommit;
		std::uint32_t peBaseAddress;
		std::uint32_t peImageSize;
		std::uint32_t peChecksum;
		std::uint32_t peTimeDate;
		std::uint32_t debugPathAddress;
		std::uint32_t debugFilenameAddress;
		std::uint32_t debugUnicodeFilenameAddress;
		std::uint32_t encodedKernelThunkAddress;
	};

	struct XbeSection
	{
		std::uint32_t flags;
		std::uint32_t virtualAddress;
		std::uint32_t virtualSize;
		std::uint32_t rawAddress;
		std::uint32_t rawSize;
		std::uint32_t nameAddress;
		std::uint32_t referenceCount;
		std::uint32_t headReferenceAddress;
		std::uint32_t tailReferenceAddress;
		std::uint8_t digest[20];
	};
#pragma pack(pop)

	static_assert(sizeof(XbeHeader) == 0x15C);
	static_assert(sizeof(XbeSection) == 56);

	template<typename T>
	T KernelImageRead(std::uint32_t address, void* opaque)
	{
		auto* image = static_cast<std::vector<std::uint8_t>*>(opaque);
		T value = 0;
		if (image && address >= KernelVirtualMapBase) {
			const std::uint64_t offset = static_cast<std::uint64_t>(address) - KernelVirtualMapBase;
			if (offset + sizeof(value) <= image->size()) std::memcpy(&value, image->data() + offset, sizeof(value));
		}
		return value;
	}

	std::uint8_t KernelImageRead8(std::uint32_t address, void* opaque) { return KernelImageRead<std::uint8_t>(address, opaque); }
	std::uint16_t KernelImageRead16(std::uint32_t address, void* opaque) { return KernelImageRead<std::uint16_t>(address, opaque); }
	std::uint32_t KernelImageRead32(std::uint32_t address, void* opaque) { return KernelImageRead<std::uint32_t>(address, opaque); }
	std::uint64_t KernelImageRead64(std::uint32_t address, void* opaque) { return KernelImageRead<std::uint64_t>(address, opaque); }
	template<typename T>
	void KernelImageWrite(std::uint32_t address, T value, void* opaque)
	{
		auto* image = static_cast<std::vector<std::uint8_t>*>(opaque);
		if (image && address >= KernelVirtualMapBase) {
			const std::uint64_t offset = static_cast<std::uint64_t>(address) - KernelVirtualMapBase;
			if (offset + sizeof(value) <= image->size()) std::memcpy(image->data() + offset, &value, sizeof(value));
		}
	}

	void KernelImageWrite8(std::uint32_t address, std::uint8_t value, void* opaque) { KernelImageWrite(address, value, opaque); }
	void KernelImageWrite16(std::uint32_t address, std::uint16_t value, void* opaque) { KernelImageWrite(address, value, opaque); }
	void KernelImageWrite32(std::uint32_t address, std::uint32_t value, void* opaque) { KernelImageWrite(address, value, opaque); }
	void KernelImageWrite64(std::uint32_t address, std::uint64_t value, void* opaque) { KernelImageWrite(address, value, opaque); }

	std::uint8_t Nv2aRead8(std::uint32_t address, void* opaque) { return static_cast<CxbxUwpNv2aProducer*>(opaque)->Read8(address); }
	std::uint16_t Nv2aRead16(std::uint32_t address, void* opaque) { return static_cast<CxbxUwpNv2aProducer*>(opaque)->Read16(address); }
	std::uint32_t Nv2aRead32(std::uint32_t address, void* opaque) { return static_cast<CxbxUwpNv2aProducer*>(opaque)->Read32(address); }
	std::uint64_t Nv2aRead64(std::uint32_t address, void* opaque) { return static_cast<CxbxUwpNv2aProducer*>(opaque)->Read64(address); }
	void Nv2aWrite8(std::uint32_t address, std::uint8_t value, void* opaque) { static_cast<CxbxUwpNv2aProducer*>(opaque)->Write8(address, value); }
	void Nv2aWrite16(std::uint32_t address, std::uint16_t value, void* opaque) { static_cast<CxbxUwpNv2aProducer*>(opaque)->Write16(address, value); }
	void Nv2aWrite32(std::uint32_t address, std::uint32_t value, void* opaque) { static_cast<CxbxUwpNv2aProducer*>(opaque)->Write32(address, value); }
	void Nv2aWrite64(std::uint32_t address, std::uint64_t value, void* opaque) { static_cast<CxbxUwpNv2aProducer*>(opaque)->Write64(address, value); }

	std::uint8_t DeviceRead8(std::uint32_t address, void* opaque) { return static_cast<CxbxUwpDeviceBus*>(opaque)->ReadMmio8(address); }
	std::uint16_t DeviceRead16(std::uint32_t address, void* opaque) { return static_cast<CxbxUwpDeviceBus*>(opaque)->ReadMmio16(address); }
	std::uint32_t DeviceRead32(std::uint32_t address, void* opaque) { return static_cast<CxbxUwpDeviceBus*>(opaque)->ReadMmio32(address); }
	std::uint64_t DeviceRead64(std::uint32_t address, void* opaque) { return static_cast<CxbxUwpDeviceBus*>(opaque)->ReadMmio64(address); }
	void DeviceWrite8(std::uint32_t address, std::uint8_t value, void* opaque) { static_cast<CxbxUwpDeviceBus*>(opaque)->WriteMmio8(address, value); }
	void DeviceWrite16(std::uint32_t address, std::uint16_t value, void* opaque) { static_cast<CxbxUwpDeviceBus*>(opaque)->WriteMmio16(address, value); }
	void DeviceWrite32(std::uint32_t address, std::uint32_t value, void* opaque) { static_cast<CxbxUwpDeviceBus*>(opaque)->WriteMmio32(address, value); }
	void DeviceWrite64(std::uint32_t address, std::uint64_t value, void* opaque) { static_cast<CxbxUwpDeviceBus*>(opaque)->WriteMmio64(address, value); }
	std::uint8_t PortRead8(std::uint32_t port, void* opaque) { return static_cast<CxbxUwpDeviceBus*>(opaque)->ReadPort8(port); }
	std::uint16_t PortRead16(std::uint32_t port, void* opaque) { return static_cast<CxbxUwpDeviceBus*>(opaque)->ReadPort16(port); }
	std::uint32_t PortRead32(std::uint32_t port, void* opaque) { return static_cast<CxbxUwpDeviceBus*>(opaque)->ReadPort32(port); }
	void PortWrite8(std::uint32_t port, std::uint8_t value, void* opaque) { static_cast<CxbxUwpDeviceBus*>(opaque)->WritePort8(port, value); }
	void PortWrite16(std::uint32_t port, std::uint16_t value, void* opaque) { static_cast<CxbxUwpDeviceBus*>(opaque)->WritePort16(port, value); }
	void PortWrite32(std::uint32_t port, std::uint32_t value, void* opaque) { static_cast<CxbxUwpDeviceBus*>(opaque)->WritePort32(port, value); }

	bool InitializeKernelImage(std::vector<std::uint8_t>& image)
	{
		// KSEG0 is the writable 64 MiB physical-memory alias. The synthetic
		// xboxkrnl image occupies its first MiB, but DMA producers and devices must
		// observe writes made anywhere through 0x80000000-0x83FFFFFF.
		image.assign(PhysicalAliasMapSize, 0);
		const std::size_t base = KernelImageBase - KernelVirtualMapBase;
		if (base + 0x6000 > KernelImageMapSize) return false;

		auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data() + base);
		dos->e_magic = IMAGE_DOS_SIGNATURE;
		dos->e_lfanew = sizeof(IMAGE_DOS_HEADER);
		auto* signature = reinterpret_cast<DWORD*>(image.data() + base + dos->e_lfanew);
		*signature = IMAGE_NT_SIGNATURE;
		auto* file = reinterpret_cast<IMAGE_FILE_HEADER*>(signature + 1);
		file->Machine = IMAGE_FILE_MACHINE_I386;
		file->NumberOfSections = 3;
		file->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
		file->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
		auto* optional = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(file + 1);
		optional->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
		optional->ImageBase = KernelImageBase;
		optional->SectionAlignment = 0x1000;
		optional->FileAlignment = 0x200;
		optional->SizeOfImage = KernelImageMapSize - static_cast<DWORD>(base);
		optional->SizeOfHeaders = 0x1000;
		optional->Subsystem = IMAGE_SUBSYSTEM_NATIVE;
		optional->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
		optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x2000;
		optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0x1000;

		auto* sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(optional + 1);
		auto section = [](IMAGE_SECTION_HEADER& target, const char* name, DWORD address, DWORD size, DWORD flags) {
			std::memcpy(target.Name, name, (std::min<std::size_t>)(std::strlen(name), IMAGE_SIZEOF_SHORT_NAME));
			target.Misc.VirtualSize = size; target.VirtualAddress = address; target.SizeOfRawData = size;
			target.Characteristics = flags;
		};
		section(sections[0], ".text", 0x1000, 0x1000, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
		section(sections[1], ".edata", 0x2000, 0x2000, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
		section(sections[2], ".data", 0x4000, KernelImageMapSize - static_cast<DWORD>(base) - 0x4000,
			IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
		image[base + 0x1000] = 0xC3; // Defensive RET for tools inspecting the synthetic entry RVA.

		auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(image.data() + base + 0x2000);
		exports->Name = 0x2100;
		exports->Base = 1;
		exports->NumberOfFunctions = KernelExportCount;
		exports->AddressOfFunctions = 0x2200;
		std::memcpy(image.data() + base + 0x2100, "xboxkrnl.exe", 13);
		auto* functions = reinterpret_cast<DWORD*>(image.data() + base + 0x2200);
		for (std::uint32_t ordinal = 0; ordinal < KernelExportCount; ++ordinal) functions[ordinal] = 0x1000;
		return true;
	}

	std::mutex g_logMutex;
	std::wstring g_logPath;

	void AppendLog(const char* text)
	{
		std::lock_guard<std::mutex> lock(g_logMutex);
		if (g_logPath.empty() || !text) return;

		CREATEFILE2_EXTENDED_PARAMETERS parameters = { sizeof(parameters) };
		parameters.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
		HANDLE file = CreateFile2FromAppW(g_logPath.c_str(), FILE_APPEND_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_ALWAYS, &parameters);
		if (file == INVALID_HANDLE_VALUE) return;
		DWORD written = 0;
		WriteFile(file, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
		CloseHandle(file);
	}

	void Lib86CpuLog(log_level level, const unsigned, const char* format, ...)
	{
		char message[2048] = {};
		va_list args;
		va_start(args, format);
		vsnprintf_s(message, _TRUNCATE, format, args);
		va_end(args);
		// lib86cpu emits one debug line for every translated guest instruction.
		// Persisting each line through CreateFile2FromApp/WriteFile/CloseHandle
		// effectively serializes the JIT on package storage and can make a title
		// appear hung during startup. Keep diagnostic debug messages, but discard
		// the address-prefixed instruction disassembly in normal UWP execution.
		if (level == log_level::debug && message[0] == '0' && message[1] == 'x') return;
		const char* prefix = level == log_level::error ? "[lib86cpu:error] " :
			level == log_level::warn ? "[lib86cpu:warn] " :
			level == log_level::debug ? "[lib86cpu:debug] " : "[lib86cpu] ";
		char line[2200] = {};
		sprintf_s(line, "%s%s\r\n", prefix, message);
		AppendLog(line);
	}

	HRESULT ReadAllBytes(const wchar_t* path, std::vector<std::uint8_t>& bytes)
	{
		CREATEFILE2_EXTENDED_PARAMETERS parameters = { sizeof(parameters) };
		parameters.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
		HANDLE file = CreateFile2FromAppW(path, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, &parameters);
		if (file == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());

		LARGE_INTEGER size = {};
		if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 512ll * 1024 * 1024) {
			HRESULT result = HRESULT_FROM_WIN32(GetLastError() ? GetLastError() : ERROR_FILE_TOO_LARGE);
			CloseHandle(file);
			return result;
		}
		bytes.resize(static_cast<std::size_t>(size.QuadPart));
		std::size_t offset = 0;
		while (offset < bytes.size()) {
			DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, 1u << 20));
			DWORD read = 0;
			if (!ReadFile(file, bytes.data() + offset, chunk, &read, nullptr) || read == 0) {
				HRESULT result = HRESULT_FROM_WIN32(GetLastError() ? GetLastError() : ERROR_HANDLE_EOF);
				CloseHandle(file);
				return result;
			}
			offset += read;
		}
		CloseHandle(file);
		return S_OK;
	}

	HRESULT ReadBootImage(const wchar_t* path, std::vector<std::uint8_t>& bytes,
		bool& isXiso, std::uint64_t& imageOffset, const char* xisoEntry = nullptr)
	{
		isXiso = false;
		imageOffset = 0;
		CREATEFILE2_EXTENDED_PARAMETERS parameters = { sizeof(parameters) };
		parameters.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
		HANDLE file = CreateFile2FromAppW(path, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, &parameters);
		if (file == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());
		std::uint32_t magic = 0; DWORD read = 0;
		const BOOL readOk = ReadFile(file, &magic, sizeof(magic), &read, nullptr);
		CloseHandle(file);
		if (!readOk) return HRESULT_FROM_WIN32(GetLastError());
		if (read == sizeof(magic) && magic == XbeMagic) return ReadAllBytes(path, bytes);

		CxbxUwpXisoReader xiso;
		HRESULT result = xiso.Mount(path);
		if (FAILED(result)) return result;
		const char* entry = xisoEntry && *xisoEntry ? xisoEntry : "default.xbe";
		result = xiso.ReadAll(entry, bytes, &imageOffset);
		if (FAILED(result)) return result;
		isXiso = true;
		char line[256] = {};
		sprintf_s(line, "[uwp-executor] XISO montado sem copia; %s em 0x%llX (%zu bytes).\r\n",
			entry, static_cast<unsigned long long>(imageOffset), bytes.size());
		AppendLog(line);
		return S_OK;
	}

	void ConfigureFlatProtectedMode(cpu_t* cpu, std::uint32_t entry, std::uint32_t stack)
	{
		regs_t* regs = get_regs_ptr(cpu);
		// Xbox runs its Pentium III-class CPU with protected mode, monitor
		// coprocessor and native x87 exception reporting enabled. Leaving CR0.NE
		// clear makes lib86cpu select the obsolete DOS FERR/IGNNE protocol and
		// abort as soon as a translated block contains FWAIT or an x87 operation
		// that checks pending exceptions.
		constexpr std::uint32_t Cr0ProtectedMode = 1u << 0;
		constexpr std::uint32_t Cr0MonitorCoprocessor = 1u << 1;
		constexpr std::uint32_t Cr0NumericError = 1u << 5;
		constexpr std::uint32_t Cr0Emulation = 1u << 2;
		constexpr std::uint32_t Cr0TaskSwitched = 1u << 3;
		constexpr std::uint32_t Cr4OsFxsaveFxrstor = 1u << 9;
		constexpr std::uint32_t Cr4OsXmmExceptions = 1u << 10;
		// The HLE kernel never executes the retail kernel bootstrap which normally
		// enables the Pentium III SSE state. lib86cpu correctly raises #UD for SSE
		// while CR4.OSFXSR is clear, which then triple-faults because there is no
		// LLE kernel IDT. Reproduce the post-bootstrap Xbox control-register state.
		regs->cr0 &= ~(Cr0Emulation | Cr0TaskSwitched);
		regs->cr0 |= Cr0ProtectedMode | Cr0MonitorCoprocessor | Cr0NumericError;
		regs->cr4 |= Cr4OsFxsaveFxrstor | Cr4OsXmmExceptions;
		regs->eip = entry;
		regs->cs = 0;
		regs->cs_hidden.base = 0;
		regs->cs_hidden.limit = 0xFFFFFFFF;
		regs->cs_hidden.flags = 1u << 22;
		regs->ss_hidden.base = 0;
		regs->ss_hidden.limit = 0xFFFFFFFF;
		regs->ss_hidden.flags = 1u << 22;
		regs->ds_hidden.base = regs->es_hidden.base = regs->fs_hidden.base = regs->gs_hidden.base = 0;
		regs->ds_hidden.limit = regs->es_hidden.limit = regs->fs_hidden.limit = regs->gs_hidden.limit = 0xFFFFFFFF;
		regs->ds_hidden.flags = regs->es_hidden.flags = regs->fs_hidden.flags = regs->gs_hidden.flags = 1u << 22;
		regs->esp = stack;
		regs->ebp = stack;
	}

	HRESULT RunJitSelfTest()
	{
		cpu_t* cpu = nullptr;
		const lc86_status createStatus = cpu_new(XboxRamSize, cpu);
		if (!LC86_SUCCESS(createStatus)) {
			const std::string detail = get_last_error();
			char line[512] = {};
			sprintf_s(line, "[uwp-executor:error] cpu_new falhou no autoteste (status %d): %s.\r\n",
				static_cast<int>(createStatus), detail.empty() ? "sem detalhe" : detail.c_str());
			AppendLog(line);
			return createStatus == lc86_status::no_memory ? E_OUTOFMEMORY : E_FAIL;
		}
		const std::uint8_t code[] = {
			0xC7, 0x05, 0x00, 0x20, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, // mov dword [0x2000],12345678h
			0x6A, 0x20,                                                 // push 32
			0xFF, 0x15, 0x00, 0x30, 0x00, 0x00,                         // call [kernel thunk 14]
			0xA3, 0x04, 0x20, 0x00, 0x00,                               // mov [0x2004],eax
			0x50,                                                       // push eax
			0xFF, 0x15, 0x04, 0x30, 0x00, 0x00,                         // call [kernel thunk 17]
			0xF4 // hlt
		};
		std::uint8_t* ram = get_ram_ptr(cpu);
		std::memcpy(ram + 0x1000, code, sizeof(code));
		const std::uint32_t testThunks[] = { 0x8000000E, 0x80000011, 0 };
		std::memcpy(ram + 0x3000, testThunks, sizeof(testThunks));
		lc86_status status = mem_init_region_ram(cpu, 0, XboxRamSize);
		if (LC86_SUCCESS(status)) status = cpu_set_flags(cpu, CPU_INTEL_SYNTAX | CPU_ABORT_ON_HLT);
		auto kernelBridge = std::make_unique<CxbxUwpKernelBridge>(cpu, ram, &AppendLog);
		if (LC86_SUCCESS(status) && FAILED(kernelBridge->Install(0x3000 ^ 0x5B6D40B6, false, 0x10000))) {
			status = lc86_status::internal_error;
		}
		if (LC86_SUCCESS(status)) {
			ConfigureFlatProtectedMode(cpu, 0x1000, 0x10000);
			status = cpu_run(cpu);
		}
		std::uint32_t value = 0, allocation = 0;
		std::memcpy(&value, ram + 0x2000, sizeof(value));
		std::memcpy(&allocation, ram + 0x2004, sizeof(allocation));
		kernelBridge.reset();
		cpu_free(cpu);
		if (value != 0x12345678 || allocation < 0x01000000 || allocation >= XboxRamSize) {
			AppendLog("[uwp-executor:error] O autoteste JIT/kernel bridge nao produziu o resultado esperado.\r\n");
			return E_FAIL;
		}
		AppendLog("[uwp-executor] Autoteste JIT e thunk x86-em-x64 concluido.\r\n");
		return S_OK;
	}

	bool RangeFits(std::uint64_t start, std::uint64_t size, std::uint64_t limit)
	{
		return start <= limit && size <= limit - start;
	}

	class Executor final
	{
	public:
		HRESULT Boot(const CxbxUwpBootConfig* config, const std::string& xisoEntry = {},
			const std::array<std::uint8_t, 4096>* launchData = nullptr,
			bool preserveLog = false)
		{
			if (!config || config->size < sizeof(CxbxUwpBootConfig) || !config->gamePath ||
				!config->logPath || !config->dataRoot || !config->gameRoot) return E_INVALIDARG;
			Stop();
			if (!preserveLog) {
				std::lock_guard<std::mutex> logLock(g_logMutex);
				g_logPath = config->logPath;
				CREATEFILE2_EXTENDED_PARAMETERS logParameters = { sizeof(logParameters) };
				logParameters.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
				HANDLE freshLog = CreateFile2FromAppW(g_logPath.c_str(), GENERIC_WRITE,
					FILE_SHARE_READ | FILE_SHARE_WRITE, CREATE_ALWAYS, &logParameters);
				if (freshLog != INVALID_HANDLE_VALUE) CloseHandle(freshLog);
			}
			register_log_func(&Lib86CpuLog);
			AppendLog(preserveLog ? "[uwp-executor] Reinicializando titulo no mesmo processo UWP.\r\n" :
				"[uwp-executor] Inicializando lib86cpu headless x64.\r\n");
			HRESULT result = S_OK;
			if (!preserveLog) {
				result = RunJitSelfTest();
				if (FAILED(result)) return result;
			}

			std::vector<std::uint8_t> image;
			bool gameIsXiso = false;
			std::uint64_t gameImageOffset = 0;
			result = ReadBootImage(config->gamePath, image, gameIsXiso, gameImageOffset,
				xisoEntry.empty() ? nullptr : xisoEntry.c_str());
			if (FAILED(result)) return result;
			if (image.size() < sizeof(XbeHeader)) return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
			const auto* header = reinterpret_cast<const XbeHeader*>(image.data());
			if (header->magic != XbeMagic || header->sectionCount == 0 || header->sectionCount > 256 ||
				header->sectionHeadersAddress < header->baseAddress ||
				!RangeFits(0, header->headerSize, image.size()) ||
				!RangeFits(header->baseAddress, header->headerSize, XboxRamSize)) {
				return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
			}
			std::uint32_t titleId = 0;
			std::array<std::uint8_t, 16> certificateLanKey = {};
			std::array<std::uint8_t, 16> certificateSignatureKey = {};
			std::array<std::uint8_t, 16 * 16> certificateAlternateKeys = {};
			if (header->certificateAddress >= header->baseAddress) {
				const std::uint64_t certificateOffset = static_cast<std::uint64_t>(header->certificateAddress) - header->baseAddress;
				std::uint32_t certificateSize = 0;
				if (RangeFits(certificateOffset, 12, image.size())) {
					std::memcpy(&certificateSize, image.data() + certificateOffset, sizeof(certificateSize));
					std::memcpy(&titleId, image.data() + certificateOffset + 8, sizeof(titleId));
				}
				if (certificateSize >= 0xD0 && RangeFits(certificateOffset + 0xB0, 32, image.size())) {
					std::memcpy(certificateLanKey.data(), image.data() + certificateOffset + 0xB0, 16);
					std::memcpy(certificateSignatureKey.data(), image.data() + certificateOffset + 0xC0, 16);
				}
				const std::uint32_t alternateBytes = certificateSize > 0xD0 ?
					(std::min<std::uint32_t>)(certificateSize - 0xD0, static_cast<std::uint32_t>(certificateAlternateKeys.size())) : 0;
				if (alternateBytes && RangeFits(certificateOffset + 0xD0, alternateBytes, image.size()))
					std::memcpy(certificateAlternateKeys.data(), image.data() + certificateOffset + 0xD0, alternateBytes);
			}
			const std::uint64_t sectionTableOffset =
				static_cast<std::uint64_t>(header->sectionHeadersAddress) - header->baseAddress;
			if (!RangeFits(sectionTableOffset, static_cast<std::uint64_t>(header->sectionCount) * sizeof(XbeSection), image.size())) {
				return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
			}

			cpu_t* cpu = nullptr;
			const lc86_status createStatus = cpu_new(XboxRamSize, cpu);
			if (!LC86_SUCCESS(createStatus)) {
				const std::string detail = get_last_error();
				char line[512] = {};
				sprintf_s(line, "[uwp-executor:error] cpu_new falhou no boot (status %d): %s.\r\n",
					static_cast<int>(createStatus), detail.empty() ? "sem detalhe" : detail.c_str());
				AppendLog(line);
				return createStatus == lc86_status::no_memory ? E_OUTOFMEMORY : E_FAIL;
			}
			auto fail = [this, cpu](HRESULT failure) { cpu_free(cpu); m_kernelRom.clear(); return failure; };
			std::uint8_t* ram = get_ram_ptr(cpu);
			std::memcpy(ram + header->baseAddress, image.data(),
				std::min<std::size_t>(header->headerSize, image.size()));
			const auto* sections = reinterpret_cast<const XbeSection*>(image.data() + sectionTableOffset);
			std::uint32_t imageEnd = header->baseAddress + header->headerSize;
			for (std::uint32_t index = 0; index < header->sectionCount; ++index) {
				const XbeSection& section = sections[index];
				if (!RangeFits(section.virtualAddress, section.virtualSize, XboxRamSize) ||
					!RangeFits(section.rawAddress, section.rawSize, image.size()) || section.rawSize > section.virtualSize) {
					return fail(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT));
				}
				std::memset(ram + section.virtualAddress, 0, section.virtualSize);
				std::memcpy(ram + section.virtualAddress, image.data() + section.rawAddress, section.rawSize);
				imageEnd = (std::max)(imageEnd, section.virtualAddress + section.virtualSize);
			}

			lc86_status status = mem_init_region_ram(cpu, 0, XboxRamSize);
			if (!LC86_SUCCESS(status)) {
				const std::string detail = get_last_error();
				char line[384] = {};
				sprintf_s(line, "[uwp-executor:error] mem_init_region_ram falhou (status %d): %s.\r\n",
					static_cast<int>(status), detail.empty() ? "sem detalhe" : detail.c_str());
				AppendLog(line);
				return fail(E_FAIL);
			}
			if (!InitializeKernelImage(m_kernelRom)) return fail(E_OUTOFMEMORY);
			// The synthetic kernel image needs separate storage because lib86cpu does
			// not currently model the Xbox page tables. DMA devices, however, must use
			// the same physical backing used by contiguous/system allocations and by
			// the title. Pointing NV2A at m_kernelRom made push buffers, textures and
			// framebuffers written through low guest addresses invisible to the GPU.
			auto nv2a = std::make_unique<CxbxUwpNv2aProducer>(ram, XboxRamSize, &AppendLog);
			nv2a->SetPixelShadersEnabled((config->compatibilityFlags & CxbxUwpDisablePixelShaders) == 0);
			io_handlers_t nv2aHandlers = {
				&Nv2aRead8, &Nv2aRead16, &Nv2aRead32, &Nv2aRead64,
				&Nv2aWrite8, &Nv2aWrite16, &Nv2aWrite32, &Nv2aWrite64
			};
			status = mem_init_region_io(cpu, CxbxUwpNv2aProducer::MmioBase,
				CxbxUwpNv2aProducer::MmioSize, false, nv2aHandlers, nv2a.get());
			if (!LC86_SUCCESS(status)) {
				AppendLog("[uwp-executor:error] Falha ao mapear MMIO NV2A.\r\n");
				return fail(E_FAIL);
			}
			AppendLog("[uwp-executor] MMIO NV2A e produtor de push-buffer habilitados em 0xFD000000.\r\n");
			auto devices = std::make_unique<CxbxUwpDeviceBus>(ram, XboxRamSize, config->dataRoot, &AppendLog);
			io_handlers_t deviceHandlers = {
				&DeviceRead8, &DeviceRead16, &DeviceRead32, &DeviceRead64,
				&DeviceWrite8, &DeviceWrite16, &DeviceWrite32, &DeviceWrite64
			};
			status = mem_init_region_io(cpu, CxbxUwpDeviceBus::MmioBase,
				CxbxUwpDeviceBus::MmioSize, false, deviceHandlers, devices.get());
			if (LC86_SUCCESS(status)) status = mem_init_region_io(cpu, CxbxUwpDeviceBus::McpxBase,
				CxbxUwpDeviceBus::McpxSize, false, deviceHandlers, devices.get());
			io_handlers_t portHandlers = {
				&PortRead8, &PortRead16, &PortRead32, nullptr,
				&PortWrite8, &PortWrite16, &PortWrite32, nullptr
			};
			if (LC86_SUCCESS(status)) status = mem_init_region_io(cpu, 0, 0x10000, true, portHandlers, devices.get());
			if (!LC86_SUCCESS(status)) {
				AppendLog("[uwp-executor:error] Falha ao mapear PCI/MMIO/PMIO dos dispositivos Xbox.\r\n");
				return fail(E_FAIL);
			}
			AppendLog("[uwp-executor] Barramento PCI, MMIO e PMIO completo dos dispositivos habilitado.\r\n");
			// The kernel is a virtual PE image inside the writable KSEG0 physical alias,
			// not Xbox flash ROM. Expose all retail physical RAM so CPU and DMA devices
			// share the same backing.
			io_handlers_t kernelHandlers = {
				&KernelImageRead8, &KernelImageRead16, &KernelImageRead32, &KernelImageRead64,
				&KernelImageWrite8, &KernelImageWrite16, &KernelImageWrite32, &KernelImageWrite64
			};
			status = mem_init_region_io(cpu, KernelVirtualMapBase, PhysicalAliasMapSize,
				false, kernelHandlers, &m_kernelRom);
			if (!LC86_SUCCESS(status)) {
				const std::string detail = get_last_error();
				char line[384] = {};
				sprintf_s(line, "[uwp-executor:error] Falha ao mapear a imagem virtual completa do kernel Xbox (status %d): %s.\r\n",
					static_cast<int>(status), detail.empty() ? "sem detalhe" : detail.c_str());
				AppendLog(line);
				return fail(E_FAIL);
			}
			AppendLog("[uwp-executor] Alias fisica KSEG0 mapeada em 0x80000000-0x83FFFFFF; kernel em 0x80010000-0x800FFFFF.\r\n");
			std::uint16_t kernelSignature = 0;
			std::uint64_t kernelBytesRead = 0;
			status = mem_read_block_virt(cpu, KernelImageBase, sizeof(kernelSignature),
				reinterpret_cast<std::uint8_t*>(&kernelSignature), &kernelBytesRead);
			if (!LC86_SUCCESS(status) || kernelBytesRead != sizeof(kernelSignature) || kernelSignature != IMAGE_DOS_SIGNATURE) {
				AppendLog("[uwp-executor:error] A verificacao da imagem PE virtual do kernel Xbox falhou.\r\n");
				return fail(E_FAIL);
			}
			// cpu_run_until enables the internal timeout mode itself. CPU_ABORT_ON_HLT
			// is intentionally limited to RunJitSelfTest; Xbox titles use HLT while
			// waiting for scheduler/device interrupts.
			status = cpu_set_flags(cpu, CPU_INTEL_SYNTAX);
			if (!LC86_SUCCESS(status)) {
				const std::string detail = get_last_error();
				char line[384] = {};
				sprintf_s(line, "[uwp-executor:error] cpu_set_flags falhou (status %d): %s.\r\n",
					static_cast<int>(status), detail.empty() ? "sem detalhe" : detail.c_str());
				AppendLog(line);
				return fail(E_FAIL);
			}
			auto kernelBridge = std::make_unique<CxbxUwpKernelBridge>(cpu, ram, &AppendLog,
				config->dataRoot, config->gameRoot, titleId, config->gamePath,
				gameIsXiso, gameImageOffset, certificateLanKey.data(),
				certificateSignatureKey.data(), certificateAlternateKeys.data(),
				m_kernelRom.data(), m_kernelRom.size());
			{ char line[128] = {}; sprintf_s(line, "[uwp-executor] Title ID: %08X.\r\n", titleId); AppendLog(line); }
			std::uint32_t selectedConsoleType = config->consoleType;
			if (selectedConsoleType == 0u) {
				const auto retailThunk = header->encodedKernelThunkAddress ^ 0x5B6D40B6u;
				const auto debugThunk = header->encodedKernelThunkAddress ^ 0xEFB1F152u;
				selectedConsoleType = RangeFits(retailThunk, 4, XboxRamSize) ? 1u :
					(RangeFits(debugThunk, 4, XboxRamSize) ? 2u : 1u);
			}
			result = kernelBridge->Install(header->encodedKernelThunkAddress, selectedConsoleType, imageEnd);
			if (FAILED(result)) return fail(result);
			if (launchData) kernelBridge->RestoreLaunchData(launchData->data(), launchData->size());

			const std::uint32_t retailEntry = header->encodedEntryAddress ^ RetailEntryXor;
			const std::uint32_t debugEntry = header->encodedEntryAddress ^ DebugEntryXor;
			const std::uint32_t chihiroEntry = header->encodedEntryAddress ^ ChihiroEntryXor;
			auto isExecutableEntry = [sections, header](std::uint32_t address) {
				for (std::uint32_t index = 0; index < header->sectionCount; ++index) {
					const auto& section = sections[index];
					if ((section.flags & 4) && address >= section.virtualAddress &&
						address < static_cast<std::uint64_t>(section.virtualAddress) + section.virtualSize) return true;
				}
				return false;
			};
			const std::uint32_t entry = selectedConsoleType == 2u
				? (isExecutableEntry(debugEntry) ? debugEntry : retailEntry)
				: (selectedConsoleType == 3u ? chihiroEntry :
					(isExecutableEntry(retailEntry) ? retailEntry : debugEntry));
			if (!isExecutableEntry(entry)) return fail(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT));
			const std::uint32_t stackBase = static_cast<std::uint32_t>(XboxRamSize - 0x1000);
			ConfigureFlatProtectedMode(cpu, entry, stackBase);
			result = kernelBridge->InitializeTls(header->tlsAddress, stackBase);
			if (FAILED(result)) return fail(result);

			const std::wstring bootDataRoot(config->dataRoot);
			const std::wstring bootLogPath(config->logPath);
			const std::wstring bootGameRoot(config->gameRoot);
			const std::uint32_t bootConsoleType = config->consoleType;
			const std::uint32_t bootCompatibilityFlags = config->compatibilityFlags;
			{
				std::lock_guard<std::mutex> lock(m_mutex);
				m_cpu = cpu;
				m_kernelBridge = std::move(kernelBridge);
				m_nv2a = std::move(nv2a);
				m_devices = std::move(devices);
				m_running = true;
				m_thread = std::thread([this, cpu, bootDataRoot, bootLogPath, bootGameRoot,
					bootConsoleType, bootCompatibilityFlags]() {
					AppendLog("[uwp-executor] Transferindo controle para o entry point do XBE.\r\n");
					cpu_sync_state(cpu);
					lc86_status runStatus = lc86_status::success;
					try {
						for (;;) {
							runStatus = cpu_run_until(cpu, 2000);
							if (runStatus == lc86_status::timeout) {
								if (m_nv2a) m_nv2a->Tick();
								if (m_devices) m_devices->Tick();
								if (m_kernelBridge) m_kernelBridge->OnTimeslice();
								continue;
							}
							if (runStatus == lc86_status::paused) {
								while (cpu_is_suspended(cpu) && m_running) std::this_thread::sleep_for(std::chrono::milliseconds(1));
								if (m_running) continue;
							}
							break;
						}
					} catch (const std::exception& error) {
						char exceptionLine[512] = {};
						sprintf_s(exceptionLine, "[uwp-executor:error] Excecao C++ no worker de emulacao: %s.\r\n", error.what());
						AppendLog(exceptionLine);
					} catch (...) {
						AppendLog("[uwp-executor:error] Excecao nativa desconhecida no worker de emulacao.\r\n");
					}
					std::wstring rebootPath;
					std::string rebootEntry;
					std::array<std::uint8_t, 4096> rebootData = {};
					const bool reboot = m_kernelBridge &&
						m_kernelBridge->TakeRebootRequest(rebootPath, rebootEntry, rebootData);
					char line[256] = {};
					sprintf_s(line, "[uwp-executor] CPU encerrada com status %d: %s\r\n",
						static_cast<int>(runStatus), get_last_error().c_str());
					AppendLog(line);
					m_running = false;
					if (reboot) {
						std::thread([this, rebootPath = std::move(rebootPath),
							rebootEntry = std::move(rebootEntry), rebootData,
							bootDataRoot, bootLogPath, bootGameRoot, bootConsoleType,
							bootCompatibilityFlags]() mutable {
							CxbxUwpBootConfig next = { sizeof(CxbxUwpBootConfig), rebootPath.c_str(),
								bootDataRoot.c_str(), bootLogPath.c_str(), bootGameRoot.c_str(),
								bootConsoleType, bootCompatibilityFlags };
							const HRESULT rebootResult = Boot(&next, rebootEntry, &rebootData, true);
							if (FAILED(rebootResult)) {
								char error[192] = {};
								sprintf_s(error, "[uwp-executor:error] Reinicializacao do titulo falhou: 0x%08X.\r\n",
									static_cast<unsigned>(rebootResult));
								AppendLog(error);
							}
						}).detach();
					}
				});
			}
			return S_OK;
		}

		HRESULT Pause()
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			if (!m_cpu || !m_running) return E_ILLEGAL_METHOD_CALL;
			cpu_suspend(m_cpu, true);
			return S_OK;
		}

		HRESULT Resume()
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			if (!m_cpu || !m_running) return E_ILLEGAL_METHOD_CALL;
			cpu_resume(m_cpu);
			return S_OK;
		}

		HRESULT Stop()
		{
			cpu_t* cpu = nullptr;
			{
				std::lock_guard<std::mutex> lock(m_mutex);
				cpu = m_cpu;
				m_running = false;
				if (m_kernelBridge) m_kernelBridge->RequestStop();
				if (cpu) cpu_exit(cpu);
			}
			if (m_thread.joinable()) m_thread.join();
			{
				std::lock_guard<std::mutex> lock(m_mutex);
				m_kernelBridge.reset();
				m_nv2a.reset();
				m_devices.reset();
				if (m_cpu) cpu_free(m_cpu);
				m_cpu = nullptr;
				m_kernelRom.clear();
				m_running = false;
			}
			return S_OK;
		}

		~Executor() { Stop(); }

	private:
		std::mutex m_mutex;
		cpu_t* m_cpu = nullptr;
		std::unique_ptr<CxbxUwpKernelBridge> m_kernelBridge;
		std::unique_ptr<CxbxUwpNv2aProducer> m_nv2a;
		std::unique_ptr<CxbxUwpDeviceBus> m_devices;
		std::vector<std::uint8_t> m_kernelRom;
		std::thread m_thread;
		std::atomic<bool> m_running = false;
	};

	Executor& GetExecutor()
	{
		static Executor executor;
		return executor;
	}

	template<typename Callback>
	HRESULT AbiBoundary(Callback&& callback)
	{
		try {
			return callback();
		}
		catch (const std::exception& error) {
			char line[1024] = {};
			sprintf_s(line, "[uwp-executor:error] Excecao no executor: %s\r\n", error.what());
			AppendLog(line);
			return E_FAIL;
		}
		catch (...) {
			AppendLog("[uwp-executor:error] Excecao desconhecida no executor.\r\n");
			return E_FAIL;
		}
	}

	HRESULT Boot(const CxbxUwpBootConfig* config) { return AbiBoundary([config] { return GetExecutor().Boot(config); }); }
	HRESULT Pause() { return AbiBoundary([] { return GetExecutor().Pause(); }); }
	HRESULT Resume() { return AbiBoundary([] { return GetExecutor().Resume(); }); }
	HRESULT Stop() { return AbiBoundary([] { return GetExecutor().Stop(); }); }

	struct Registration
	{
		Registration()
		{
			const CxbxUwpCoreExecutor executor = {
				sizeof(CxbxUwpCoreExecutor), CXBXR_UWP_EXECUTOR_ABI_VERSION,
				&Boot, &Pause, &Resume, &Stop
			};
			CxbxUwpRegisterCoreExecutor(&executor);
		}
	};

	Registration g_registration;
}
