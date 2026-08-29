#include "UwpKernelBridge.h"
#include "UwpBrokeredFileAccess.h"
#include "UwpDeviceBus.h"
#include "UwpNv2aProducer.h"
#include "UwpXisoReader.h"
#include "UwpXboxPublicKey.h"
#include "../../../common/crypto/EmuSha.h"
#include "../../../common/crypto/LibRc4.h"
#include "../../../common/crypto/EmuDes.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cwctype>
#include <cstring>
#include <cstdio>
#include <limits>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{
	std::atomic<CxbxUwpOpenBrokeredFile> g_openBrokeredFile{ nullptr };
	std::atomic<CxbxUwpEnumerateBrokeredDirectory> g_enumerateBrokeredDirectory{ nullptr };
}

void CxbxUwpRegisterBrokeredFileAccess(CxbxUwpOpenBrokeredFile openFile,
	CxbxUwpEnumerateBrokeredDirectory enumerateDirectory)
{
	g_openBrokeredFile.store(openFile, std::memory_order_release);
	g_enumerateBrokeredDirectory.store(enumerateDirectory, std::memory_order_release);
}

HRESULT CxbxUwpOpenBrokeredGameFile(const wchar_t* relativePath, bool directory,
	std::uint32_t desiredAccess, std::uint32_t shareAccess, std::uint32_t disposition,
	std::uint32_t options, HANDLE* handle)
{
	const auto callback = g_openBrokeredFile.load(std::memory_order_acquire);
	return callback ? callback(relativePath, directory, desiredAccess, shareAccess,
		disposition, options, handle) : HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
}

HRESULT CxbxUwpEnumerateBrokeredGameDirectory(const wchar_t* relativePath,
	const wchar_t* mask, std::vector<WIN32_FIND_DATAW>& entries)
{
	const auto callback = g_enumerateBrokeredDirectory.load(std::memory_order_acquire);
	return callback ? callback(relativePath, mask, &entries) : HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
}

namespace
{
	constexpr std::uint32_t XboxRamSize = 64u * 1024 * 1024;
	constexpr std::uint32_t RetailThunkXor = 0x5B6D40B6;
	constexpr std::uint32_t DebugThunkXor = 0xEFB1F152;
	constexpr std::uint32_t ChihiroThunkXor = 0x2290059D;
	constexpr std::uint32_t DataBase = 0x03EC0000;
	// Some exported variables (notably the alternate signature keys and the
	// public RSA key) are considerably larger than the old 64-byte slot.  A
	// 512-byte slot keeps every export independent while still fitting below
	// the thunk stubs.
	constexpr std::uint32_t DataStride = 512;
	constexpr std::uint32_t KernelGlobalsBase = 0x03EF8000;
	constexpr std::uint32_t StubBase = 0x03F00000;
	constexpr std::uint32_t StubStride = 16;
	constexpr std::uint32_t MaxOrdinal = 378;
	constexpr std::uint32_t ExceptionReturnOrdinal = 379;
	constexpr std::uint32_t ThreadReturnOrdinal = 380;
	constexpr std::uint32_t ApcReturnOrdinal = 381;
	constexpr std::uint32_t DpcReturnOrdinal = 382;
	constexpr std::uint32_t InterruptReturnOrdinal = 383;
	constexpr std::uint32_t SynchronizeReturnOrdinal = 384;
	constexpr std::uint32_t DriverReturnOrdinal = 385;
	constexpr std::uint32_t ThreadNotifyReturnOrdinal = 386;
	constexpr std::uint32_t UnwindReturnOrdinal = 403;
	constexpr std::uint32_t TlsReturnOrdinal = 404;
	constexpr std::uint32_t ShutdownReturnOrdinal = 405;
	constexpr std::uint32_t CryptoRomBaseOrdinal = 387;
	constexpr std::uint32_t CryptoRomLastOrdinal = CryptoRomBaseOrdinal + 15;
	constexpr std::uint32_t StatusNotImplemented = 0xC0000002;
	constexpr std::uint32_t StatusSuccess = 0;
	constexpr std::uint32_t StatusTimeout = 0x00000102;
	constexpr std::uint32_t StatusAlerted = 0x00000101;
	constexpr std::uint32_t StatusInvalidHandle = 0xC0000008;
	constexpr std::uint32_t StatusInvalidParameter = 0xC000000D;
	constexpr std::uint32_t StatusAccessDenied = 0xC0000022;
	constexpr std::uint32_t StatusObjectNameNotFound = 0xC0000034;
	constexpr std::uint32_t StatusObjectNameCollision = 0xC0000035;
	constexpr std::uint32_t StatusEndOfFile = 0xC0000011;
	constexpr std::uint32_t StatusBufferTooSmall = 0xC0000023;
	constexpr std::uint32_t StatusCancelled = 0xC0000120;
	constexpr std::uint32_t StatusUserApc = 0x000000C0;
	constexpr std::uint32_t StatusNoMoreFiles = 0x80000006;
	constexpr std::uint32_t StatusBufferOverflow = 0x80000005;
	constexpr std::uint32_t StatusInvalidDeviceRequest = 0xC0000010;
	constexpr std::uint32_t StatusNoMemory = 0xC0000017;
	constexpr std::uint32_t StatusMemoryNotAllocated = 0xC00000A0;
	constexpr std::uint32_t StatusNoncontinuableException = 0xC0000025;
	constexpr std::uint32_t StatusInvalidDisposition = 0xC0000026;
	constexpr std::uint32_t ExceptionNoncontinuable = 0x00000001;
	constexpr std::uint32_t ExceptionNestedCall = 0x00000010;
	constexpr std::uint32_t XboxMemCommit = 0x1000;
	constexpr std::uint32_t XboxMemReserve = 0x2000;
	constexpr std::uint32_t XboxMemDecommit = 0x4000;
	constexpr std::uint32_t XboxMemRelease = 0x8000;
	constexpr std::uint32_t FileCreated = 2;
	constexpr std::uint32_t FileOpened = 1;

	bool MatchFileMask(const std::string& name, const std::string& mask)
	{
		std::size_t n = 0, m = 0, star = std::string::npos, retry = 0;
		while (n < name.size()) {
			if (m < mask.size() && (mask[m] == '?' || std::toupper(static_cast<unsigned char>(mask[m])) ==
				std::toupper(static_cast<unsigned char>(name[n])))) { ++n; ++m; }
			else if (m < mask.size() && mask[m] == '*') { star = m++; retry = n; }
			else if (star != std::string::npos) { m = star + 1; n = ++retry; }
			else return false;
		}
		while (m < mask.size() && mask[m] == '*') ++m;
		return m == mask.size();
	}

	std::wstring NormalizeObjectName(std::wstring name)
	{
		std::replace(name.begin(), name.end(), L'/', L'\\');
		while (name.size() > 1 && name.back() == L'\\') name.pop_back();
		for (auto& character : name) character = static_cast<wchar_t>(std::towupper(character));
		return name;
	}

	std::atomic<CxbxUwpKernelBridge*> g_activeBridge = nullptr;
	std::mutex g_activeBridgeMutex;

	template<std::size_t Ordinal>
	void KernelHook()
	{
		if (auto* bridge = g_activeBridge.load(std::memory_order_acquire)) {
			bridge->Dispatch(static_cast<std::uint32_t>(Ordinal));
		}
	}

	template<std::size_t... Ordinals>
	constexpr std::array<hook_t, sizeof...(Ordinals)> MakeHookTable(std::index_sequence<Ordinals...>)
	{
		return { &KernelHook<Ordinals>... };
	}

	constexpr auto HookTable = MakeHookTable(std::make_index_sequence<ShutdownReturnOrdinal + 1>{});
	// Stock Xbox HDD partition table, expressed in 512-byte sectors. Entry zero
	// represents the whole raw disk; entries 1-5 match the retail layout.
	constexpr std::array<std::uint32_t, 8> XboxPartitionLbaStart = {
		0x00000000u, 0x0055F400u, 0x00465400u, 0x00000400u,
		0x00177400u, 0x002EE400u, 0x00000000u, 0x00000000u
	};
	constexpr std::array<std::uint32_t, 8> XboxPartitionLbaSize = {
		0x01400000u, 0x009896B0u, 0x000FA000u, 0x00177000u,
		0x00177000u, 0x00177000u, 0x00000000u, 0x00000000u
	};
	constexpr std::uint64_t XboxPartitionBytes(std::uint32_t partition)
	{
		return partition < XboxPartitionLbaSize.size() ?
			static_cast<std::uint64_t>(XboxPartitionLbaSize[partition]) * 512ull : 0ull;
	}
	struct CryptoOverrideGuard
	{
		std::array<std::uint32_t, 16>* values = nullptr;
		std::array<std::uint32_t, 16> saved = {};
		explicit CryptoOverrideGuard(std::array<std::uint32_t, 16>* target) : values(target) { if (values) { saved = *values; values->fill(0); } }
		~CryptoOverrideGuard() { if (values) *values = saved; }
	};

	using BigWords = std::vector<std::uint32_t>;
	void BigTrim(BigWords& value) { while (value.size() > 1 && value.back() == 0) value.pop_back(); }
	int BigCompare(const BigWords& left, const BigWords& right)
	{
		std::size_t ls = left.size(), rs = right.size(); while (ls > 1 && !left[ls - 1]) --ls; while (rs > 1 && !right[rs - 1]) --rs;
		if (ls != rs) return ls < rs ? -1 : 1; for (std::size_t i = ls; i-- > 0;) if (left[i] != right[i]) return left[i] < right[i] ? -1 : 1; return 0;
	}
	void BigSubtract(BigWords& left, const BigWords& right)
	{
		std::uint64_t borrow = 0; for (std::size_t i = 0; i < left.size(); ++i) { const std::uint64_t sub = (i < right.size() ? right[i] : 0) + borrow; const std::uint64_t old = left[i]; left[i] = static_cast<std::uint32_t>(old - sub); borrow = old < sub; } BigTrim(left);
	}
	BigWords BigReduce(const BigWords& input, const BigWords& modulus)
	{
		BigWords result(1, 0); for (std::size_t word = input.size(); word-- > 0;) for (int bit = 31; bit >= 0; --bit) { std::uint64_t carry = (input[word] >> bit) & 1u; for (std::size_t i = 0; i < result.size(); ++i) { const std::uint64_t next = (static_cast<std::uint64_t>(result[i]) << 1) | carry; result[i] = static_cast<std::uint32_t>(next); carry = next >> 32; } if (carry) result.push_back(static_cast<std::uint32_t>(carry)); if (BigCompare(result, modulus) >= 0) BigSubtract(result, modulus); } return result;
	}
	BigWords BigAddMod(const BigWords& left, const BigWords& right, const BigWords& modulus)
	{
		BigWords result((std::max)(left.size(), right.size()) + 1, 0); std::uint64_t carry = 0; for (std::size_t i = 0; i + 1 < result.size(); ++i) { const std::uint64_t sum = (i < left.size() ? left[i] : 0) + static_cast<std::uint64_t>(i < right.size() ? right[i] : 0) + carry; result[i] = static_cast<std::uint32_t>(sum); carry = sum >> 32; } result.back() = static_cast<std::uint32_t>(carry); BigTrim(result); if (BigCompare(result, modulus) >= 0) BigSubtract(result, modulus); return result;
	}
	BigWords BigMultiplyMod(BigWords left, const BigWords& right, const BigWords& modulus)
	{
		left = BigReduce(left, modulus); BigWords result(1, 0); for (std::size_t word = 0; word < right.size(); ++word) for (unsigned bit = 0; bit < 32; ++bit) { if ((right[word] >> bit) & 1u) result = BigAddMod(result, left, modulus); left = BigAddMod(left, left, modulus); } return result;
	}
	BigWords BigModExp(const BigWords& base, const BigWords& exponent, const BigWords& modulus)
	{
		if (modulus.empty() || (modulus.size() == 1 && modulus[0] == 0)) return { 0 }; BigWords result = BigReduce({ 1 }, modulus), power = BigReduce(base, modulus); for (std::size_t word = 0; word < exponent.size(); ++word) for (unsigned bit = 0; bit < 32; ++bit) { if ((exponent[word] >> bit) & 1u) result = BigMultiplyMod(result, power, modulus); power = BigMultiplyMod(power, power, modulus); } return result;
	}
	BigWords BytesToWords(const std::uint8_t* bytes, std::size_t size)
	{
		BigWords result((size + 3) / 4, 0); for (std::size_t i = 0; i < size; ++i) result[i / 4] |= static_cast<std::uint32_t>(bytes[i]) << ((i & 3) * 8); BigTrim(result); return result;
	}
	void WordsToBytes(const BigWords& words, std::uint8_t* bytes, std::size_t size)
	{
		std::memset(bytes, 0, size); for (std::size_t i = 0; i < size; ++i) if (i / 4 < words.size()) bytes[i] = static_cast<std::uint8_t>(words[i / 4] >> ((i & 3) * 8));
	}

	bool IsDataExport(std::uint32_t ordinal)
	{
		switch (ordinal) {
		case 16: case 22: case 30: case 31: case 40: case 41: case 42:
		case 64: case 70: case 71: case 88: case 89: case 102: case 120:
		case 154: case 156: case 157: case 162: case 164:
		case 240: case 245: case 249: case 259:
		case 321: case 322: case 323: case 324: case 325: case 326:
		case 353: case 354: case 355: case 356: case 357:
			return true;
		default:
			return false;
		}
	}

	constexpr std::uint32_t DataAddress(std::uint32_t ordinal)
	{
		return DataBase + ordinal * DataStride;
	}
}

struct CxbxUwpKernelBridge::KernelObject
{
	ObjectKind kind = ObjectKind::Event;
	HANDLE nativeHandle = INVALID_HANDLE_VALUE;
	HANDLE findHandle = INVALID_HANDLE_VALUE;
	std::wstring path;
	std::wstring findMask;
	std::wstring target;
	std::shared_ptr<KernelObject> linkTarget;
	std::uint32_t desiredAccess = 0;
	std::uint32_t openOptions = 0;
	std::deque<std::array<std::uint32_t, 4>> completions;
	bool manualReset = false;
	bool signaled = false;
	std::int32_t count = 0;
	std::int32_t limit = 0;
	std::uint32_t ownerThreadId = 0;
	std::uint32_t recursionCount = 0;
	bool abandoned = false;
	std::uint32_t guestAddress = 0;
	std::uint32_t allocationBase = 0;
	std::uint32_t bodyAllocation = 0;
	std::uint32_t guestBodySize = 0;
	std::uint32_t objectType = 0;
	std::uint32_t threadId = 0;
	std::uint32_t references = 0;
	bool permanent = false;
	bool attached = false;
	bool timerActive = false;
	std::uint32_t timerDpc = 0;
	std::uint32_t timerApcRoutine = 0;
	std::uint32_t timerApcContext = 0;
	std::uint32_t timerThreadId = 0;
	bool timerApcUserMode = false;
	std::chrono::steady_clock::time_point due = {};
	std::chrono::milliseconds period = {};
	bool deleteOnClose = false;
	bool xiso = false;
	bool xisoVolume = false;
	bool brokeredOptical = false;
	bool rawDevice = false;
	std::uint32_t partitionNumber = 0xFFFFFFFFu;
	CxbxUwpXisoEntry xisoEntry;
	std::uint64_t xisoPosition = 0;
	std::vector<CxbxUwpXisoEntry> xisoDirectory;
	std::vector<WIN32_FIND_DATAW> hostDirectory;

	~KernelObject()
	{
		if (nativeHandle != INVALID_HANDLE_VALUE) CloseHandle(nativeHandle);
		if (findHandle != INVALID_HANDLE_VALUE) FindClose(findHandle);
		if (deleteOnClose && kind == ObjectKind::File && !path.empty()) DeleteFileFromAppW(path.c_str());
		if (deleteOnClose && kind == ObjectKind::Directory && objectType == DataAddress(71) && !path.empty()) RemoveDirectoryFromAppW(path.c_str());
	}
};

CxbxUwpKernelBridge::CxbxUwpKernelBridge(cpu_t* cpu, std::uint8_t* ram, LogCallback logger,
	const wchar_t* dataRoot, const wchar_t* gameRoot, std::uint32_t titleId, const wchar_t* gamePath,
	bool gameIsXiso, std::uint64_t gameImageOffset, const std::uint8_t* certificateLanKey,
	const std::uint8_t* certificateSignatureKey, const std::uint8_t* certificateAlternateKeys,
	std::uint8_t* kernelVirtualMemory, std::size_t kernelVirtualMemorySize)
	: m_cpu(cpu), m_ram(ram),
	  m_kernelVirtualMemory(kernelVirtualMemory), m_kernelVirtualMemorySize(kernelVirtualMemorySize),
	  m_regs(get_regs_ptr(cpu)), m_logger(logger),
	  m_dataRoot(dataRoot ? dataRoot : L""), m_gameRoot(gameRoot ? gameRoot : L""),
	  m_gamePath(gamePath ? gamePath : L""), m_gameImageOffset(gameImageOffset), m_titleId(titleId)
{
	if (certificateLanKey) std::memcpy(m_certificateLanKey.data(), certificateLanKey, m_certificateLanKey.size());
	if (certificateSignatureKey) std::memcpy(m_certificateSignatureKey.data(), certificateSignatureKey, m_certificateSignatureKey.size());
	if (certificateAlternateKeys) std::memcpy(m_certificateAlternateKeys.data(), certificateAlternateKeys, m_certificateAlternateKeys.size());
	while (m_dataRoot.size() > 3 && (m_dataRoot.back() == L'\\' || m_dataRoot.back() == L'/')) {
		m_dataRoot.pop_back();
	}
	while (m_gameRoot.size() > 3 && (m_gameRoot.back() == L'\\' || m_gameRoot.back() == L'/')) {
		m_gameRoot.pop_back();
	}
	// The retail Xbox always exposes its fixed HDD partitions.  LocalFolder is
	// the writable backing store for them; opening \Device\Harddisk0\PartitionN
	// with FILE_OPEN must therefore succeed even on a fresh installation.
	if (!m_dataRoot.empty()) {
		for (unsigned partition = 0; partition <= 7; ++partition) {
			const std::wstring path = m_dataRoot + L"\\Partition" + std::to_wstring(partition);
			if (!CreateDirectoryFromAppW(path.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS && m_logger) {
				char line[192] = {};
				sprintf_s(line, "[uwp-file:error] Falha ao criar particao virtual %u (Win32 %lu).\r\n",
					partition, GetLastError());
				m_logger(line);
			}
		}
		const std::wstring partition1 = m_dataRoot + L"\\Partition1";
		for (const wchar_t* child : { L"TDATA", L"UDATA" }) {
			const std::wstring path = partition1 + L"\\" + child;
			CreateDirectoryFromAppW(path.c_str(), nullptr);
		}
	}
	if (gameIsXiso) {
		m_xiso = std::make_unique<CxbxUwpXisoReader>();
		if (FAILED(m_xiso->Mount(m_gamePath.c_str()))) m_xiso.reset();
	}
	auto dwordSetting = [this](std::uint32_t index, std::uint32_t value) {
		auto& bytes = m_nonVolatileSettings[index]; bytes.resize(4);
		std::memcpy(bytes.data(), &value, sizeof(value));
	};
	for (std::uint32_t index = 0; index <= 0x12; ++index) dwordSetting(index, 0);
	dwordSetting(7, 1);       // English
	dwordSetting(0x12, 1);    // DVD region 1
	m_nonVolatileSettings[0x100].assign(12, 0);
	m_nonVolatileSettings[0x101] = { 0x00, 0x50, 0xF2, 0x00, 0x00, 0x01 };
	m_nonVolatileSettings[0x102].assign(16, 0);
	dwordSetting(0x103, 1);   // NTSC-M / North America AV region
	dwordSetting(0x104, 1);   // North America game region
	m_nonVolatileSettings[0xFF].assign(96, 0);
	m_nonVolatileSettings[0xFFFE].assign(48, 0);
	m_nonVolatileSettings[0xFFFF].assign(256, 0);
}

CxbxUwpKernelBridge::~CxbxUwpKernelBridge()
{
	RequestStop();
	{
		std::lock_guard<std::mutex> producerLock(g_activeBridgeMutex);
		CxbxUwpKernelBridge* expected = this;
		g_activeBridge.compare_exchange_strong(expected, nullptr, std::memory_order_acq_rel);
	}
	{
		std::lock_guard<std::mutex> lock(m_objectMutex);
		m_handles.clear();
		m_dispatcherObjects.clear();
		m_guestObjects.clear();
	}
}

void CxbxUwpKernelBridge::RequestStop()
{
	m_stopRequested.store(true, std::memory_order_release);
	m_objectChanged.notify_all();
}

bool CxbxUwpKernelBridge::TakeRebootRequest(std::wstring& hostPath,
	std::string& xisoEntry, std::array<std::uint8_t, 4096>& launchData)
{
	if (!m_rebootRequested) return false;
	hostPath = std::move(m_rebootHostPath);
	xisoEntry = std::move(m_rebootXisoEntry);
	launchData = m_rebootLaunchData;
	m_rebootRequested = false;
	return !hostPath.empty();
}

void CxbxUwpKernelBridge::RestoreLaunchData(const std::uint8_t* launchData,
	std::size_t size)
{
	if (!launchData || size < 4096) return;
	std::uint32_t page = 0;
	if (Read(DataAddress(164), page)) {
		auto* destination = GuestPointer(page, 4096);
		if (destination) std::memcpy(destination, launchData, 4096);
	}
}

void CxbxUwpKernelBridge::OnTimeslice()
{
	if (m_stopRequested.load(std::memory_order_acquire)) return;
	++m_timesliceCount;
	// Keep this deliberately sparse.  It replaces the former per-instruction
	// disassembly log and leaves enough state to diagnose a title which keeps
	// executing but never reaches the first frame.
	if (m_logger && (m_timesliceCount <= 32 ||
		(m_timesliceCount % 10000) == 0)) {
		std::array<std::uint32_t, 6> states = {};
		std::size_t apcs = 0;
		for (const auto& thread : m_threads) {
			const auto state = static_cast<std::size_t>(thread.state);
			if (state < states.size()) ++states[state];
			apcs += thread.apcs.size();
		}
		std::size_t pendingInterrupts = 0;
		{
			std::lock_guard<std::mutex> lock(m_interruptMutex);
			pendingInterrupts = m_pendingInterrupts.size();
		}
		const std::uint32_t threadId = m_currentThreadIndex < m_threads.size()
			? m_threads[m_currentThreadIndex].id : 0;
		char line[384] = {};
		sprintf_s(line,
			"[uwp-watchdog] slice=%llu EIP=0x%08X thread=%u IRQL=%u "
			"threads(Run=%u Ready=%u Wait=%u Sleep=%u Susp=%u Term=%u) "
			"IRQ=%zu DPC=%zu APC=%zu ultimo-ordinal=%u@0x%08X chamadas=%llu.\r\n",
			static_cast<unsigned long long>(m_timesliceCount), m_regs ? m_regs->eip : 0,
			threadId, static_cast<unsigned>(m_currentIrql), states[0], states[1],
			states[2], states[3], states[4], states[5], pendingInterrupts,
			m_dpcQueue.size(), apcs, m_lastDispatchedOrdinal, m_lastDispatchEip,
			static_cast<unsigned long long>(m_dispatchCount));
		m_logger(line);
	}
	UpdateExportedData();
	if (DeliverPendingInterrupt()) return;
	if (m_dpcActive || m_synchronizeActive || m_interruptActive) return;
	if (DeliverPendingDpc()) return;
	if (!m_driverFrames.empty() || m_threadNotifyActive || m_shutdownNotificationActive ||
		m_exceptionPending || m_unwindActive || (!m_threads.empty() &&
		(m_threads[m_currentThreadIndex].deliveringApc || m_threads[m_currentThreadIndex].tlsCallbacksActive))) return;
	if (m_currentIrql == 0 && m_currentThreadIndex < m_threads.size() &&
		m_threads[m_currentThreadIndex].state == ThreadState::Running &&
		DeliverPendingApc(m_threads[m_currentThreadIndex])) return;
	WakeThreads();
	SyncReadyList();
	bool preempt = false;
	if (!m_threads.empty() && m_currentThreadIndex < m_threads.size()) {
		auto& current = m_threads[m_currentThreadIndex];
		if (current.state == ThreadState::Running) {
			for (const auto& candidate : m_threads) {
				if (candidate.state == ThreadState::Runnable && candidate.priority > current.priority) { preempt = true; break; }
			}
			if (current.quantumRemaining) --current.quantumRemaining;
			Write(current.guestThread + 0x6C, current.quantumRemaining);
			if (!current.quantumRemaining) preempt = true;
		} else preempt = true;
	}
	if (preempt) SwitchThread(true);
	if (!m_interruptActive && !m_dpcActive && !m_synchronizeActive) {
		if (!DeliverPendingInterrupt()) DeliverPendingDpc();
	}
}

void CxbxUwpKernelBridge::RequestInterrupt(std::uint32_t busInterruptLevel)
{
	if (busInterruptLevel > 27 || m_stopRequested.load(std::memory_order_acquire)) return;
	std::lock_guard<std::mutex> lock(m_interruptMutex);
	if ((m_enabledInterrupts & (1u << busInterruptLevel)) == 0) return;
	auto found = m_interrupts.find(busInterruptLevel);
	if (found == m_interrupts.end() || !found->second.connected) return;
	found->second.pulsePending = true;
	if (std::find(m_pendingInterrupts.begin(), m_pendingInterrupts.end(), busInterruptLevel) == m_pendingInterrupts.end()) {
		m_pendingInterrupts.push_back(busInterruptLevel);
	}
}

void CxbxUwpKernelBridge::AssertInterrupt(std::uint32_t busInterruptLevel, std::uint32_t sourceMask)
{
	if (busInterruptLevel > 27 || !sourceMask || m_stopRequested.load(std::memory_order_acquire)) return;
	std::lock_guard<std::mutex> lock(m_interruptMutex);
	m_assertedDeviceSources[busInterruptLevel] |= sourceMask;
	auto found = m_interrupts.find(busInterruptLevel);
	if (found == m_interrupts.end() || !found->second.connected) return;
	found->second.assertedSources |= sourceMask;
	if ((m_enabledInterrupts & (1u << busInterruptLevel)) != 0 && !found->second.inService &&
		std::find(m_pendingInterrupts.begin(), m_pendingInterrupts.end(), busInterruptLevel) == m_pendingInterrupts.end()) {
		m_pendingInterrupts.push_back(busInterruptLevel);
	}
}

void CxbxUwpKernelBridge::AcknowledgeInterrupt(std::uint32_t busInterruptLevel, std::uint32_t sourceMask)
{
	if (busInterruptLevel > 27 || !sourceMask) return;
	std::lock_guard<std::mutex> lock(m_interruptMutex);
	m_assertedDeviceSources[busInterruptLevel] &= ~sourceMask;
	auto found = m_interrupts.find(busInterruptLevel);
	if (found != m_interrupts.end()) found->second.assertedSources &= ~sourceMask;
}

void CxbxUwpPulseDeviceInterrupt(std::uint32_t busInterruptLevel)
{
	std::lock_guard<std::mutex> lock(g_activeBridgeMutex);
	if (auto* bridge = g_activeBridge.load(std::memory_order_acquire)) bridge->RequestInterrupt(busInterruptLevel);
}

void CxbxUwpAssertDeviceInterrupt(std::uint32_t busInterruptLevel, std::uint32_t sourceMask)
{
	std::lock_guard<std::mutex> lock(g_activeBridgeMutex);
	if (auto* bridge = g_activeBridge.load(std::memory_order_acquire)) bridge->AssertInterrupt(busInterruptLevel, sourceMask);
}

void CxbxUwpAcknowledgeDeviceInterrupt(std::uint32_t busInterruptLevel, std::uint32_t sourceMask)
{
	std::lock_guard<std::mutex> lock(g_activeBridgeMutex);
	if (auto* bridge = g_activeBridge.load(std::memory_order_acquire)) bridge->AcknowledgeInterrupt(busInterruptLevel, sourceMask);
}

bool CxbxUwpKernelBridge::IsRangeValid(std::uint32_t address, std::size_t size) const
{
	return GuestPointer(address, size) != nullptr;
}

const std::uint8_t* CxbxUwpKernelBridge::GuestPointer(std::uint32_t address, std::size_t size) const
{
	if (address <= XboxRamSize && size <= XboxRamSize - address) return m_ram + address;
	constexpr std::uint32_t KernelVirtualBase = 0x80000000u;
	if (m_kernelVirtualMemory && address >= KernelVirtualBase) {
		const std::uint64_t offset = static_cast<std::uint64_t>(address) - KernelVirtualBase;
		if (offset <= m_kernelVirtualMemorySize && size <= m_kernelVirtualMemorySize - static_cast<std::size_t>(offset))
			return m_kernelVirtualMemory + offset;
	}
	return nullptr;
}

std::uint8_t* CxbxUwpKernelBridge::GuestPointer(std::uint32_t address, std::size_t size)
{
	return const_cast<std::uint8_t*>(static_cast<const CxbxUwpKernelBridge*>(this)->GuestPointer(address, size));
}

bool CxbxUwpKernelBridge::FillGuestMemory(std::uint32_t address, std::uint8_t value, std::size_t size)
{
	auto* destination = GuestPointer(address, size);
	if (!destination) return false;
	std::memset(destination, value, size);
	return true;
}

bool CxbxUwpKernelBridge::CopyGuestMemory(std::uint32_t destination,
	std::uint32_t source, std::size_t size, bool allowOverlap)
{
	auto* destinationPointer = GuestPointer(destination, size);
	const auto* sourcePointer = GuestPointer(source, size);
	if (!destinationPointer || !sourcePointer) return false;
	if (allowOverlap) std::memmove(destinationPointer, sourcePointer, size);
	else std::memcpy(destinationPointer, sourcePointer, size);
	return true;
}

template<typename T>
bool CxbxUwpKernelBridge::Read(std::uint32_t address, T& value) const
{
	const auto* source = GuestPointer(address, sizeof(T));
	if (!source) return false;
	std::memcpy(&value, source, sizeof(T));
	return true;
}

template<typename T>
bool CxbxUwpKernelBridge::Write(std::uint32_t address, const T& value)
{
	auto* destination = GuestPointer(address, sizeof(T));
	if (!destination) return false;
	std::memcpy(destination, &value, sizeof(T));
	return true;
}

bool CxbxUwpKernelBridge::ReadStack(std::uint32_t index, std::uint32_t& value) const
{
	return Read(m_regs->esp + 4 + index * 4, value);
}

void CxbxUwpKernelBridge::FinishStdcall(std::uint32_t argumentCount)
{
	std::uint32_t returnAddress = 0;
	if (!Read(m_regs->esp, returnAddress)) {
		cpu_exit(m_cpu);
		return;
	}
	m_regs->esp += 4 + argumentCount * 4;
	m_regs->eip = returnAddress;
}

void CxbxUwpKernelBridge::FinishCdecl()
{
	std::uint32_t returnAddress = 0; if (!Read(m_regs->esp, returnAddress)) { cpu_exit(m_cpu); return; }
	m_regs->esp += 4; m_regs->eip = returnAddress;
}

int CxbxUwpKernelBridge::FormatGuestString(std::uint32_t formatAddress,
	std::uint32_t argumentsAddress, std::string& result)
{
	result.clear(); if (!IsRangeValid(formatAddress, 1)) return -1; std::uint32_t cursor = argumentsAddress;
	auto readArg32 = [this, &cursor](std::uint32_t& value) { const bool ok = Read(cursor, value); cursor += 4; return ok; };
	auto readCharacter = [this](std::uint32_t address, char& value) {
		std::uint8_t byte = 0; if (!Read(address, byte)) return false;
		value = static_cast<char>(byte); return true;
	};
	auto appendFormatted = [&result](const std::string& spec, auto value) { char local[1024] = {}; const int needed = std::snprintf(local, sizeof(local), spec.c_str(), value); if (needed > 0) result.append(local, local + (std::min)(needed, static_cast<int>(sizeof(local) - 1))); return needed >= 0; };
	for (std::uint32_t index = 0; index < 4096 && IsRangeValid(formatAddress + index, 1); ++index) {
		char ch = 0; if (!readCharacter(formatAddress + index, ch)) return -1; if (!ch) return static_cast<int>(result.size()); if (ch != '%') { result.push_back(ch); continue; }
		std::string spec("%"); char next = 0; bool longLong = false, wide = false;
		do { if (++index >= 4096 || !readCharacter(formatAddress + index, next)) return -1; if (!next) return -1; if (next == '*') { std::uint32_t width = 0; if (!readArg32(width)) return -1; spec += std::to_string(static_cast<std::int32_t>(width)); } else spec.push_back(next); } while (std::strchr("-+ #0.'123456789*", next));
		char lookahead = 0;
		bool hasLength = false; if (next == 'h') { hasLength = true; if (readCharacter(formatAddress + index + 1, lookahead) && lookahead == 'h') { spec.push_back('h'); ++index; } }
		else if (next == 'l') { hasLength = true; wide = true; if (readCharacter(formatAddress + index + 1, lookahead) && lookahead == 'l') { spec.push_back('l'); ++index; longLong = true; } }
		else if (next == 'I') { char six = 0, four = 0; if (readCharacter(formatAddress + index + 1, six) && readCharacter(formatAddress + index + 2, four) && six == '6' && four == '4') { hasLength = true; spec += "64"; index += 2; longLong = true; } }
		char type = next; if (hasLength) { if (++index >= 4096 || !readCharacter(formatAddress + index, type)) return -1; spec.push_back(type); }
		if (type == '%') { result.push_back('%'); continue; }
		if (type == 's' || type == 'S') { std::uint32_t address = 0; if (!readArg32(address)) return -1; if (!address) { result += "(null)"; continue; } std::string text; if (wide || type == 'S') { for (std::uint32_t i = 0; i < 2048 && IsRangeValid(address + i * 2, 2); ++i) { std::uint16_t wc = 0; Read(address + i * 2, wc); if (!wc) break; text.push_back(wc < 0x80 ? static_cast<char>(wc) : '?'); } } else { for (std::uint32_t i = 0; i < 4096; ++i) { char character = 0; if (!readCharacter(address + i, character) || !character) break; text.push_back(character); } } appendFormatted(spec, text.c_str()); continue; }
		if (type == 'n') { std::uint32_t address = 0; if (!readArg32(address)) return -1; if (address) Write(address, static_cast<std::uint32_t>(result.size())); continue; }
		if (std::strchr("aAeEfFgG", type)) { std::uint64_t bits = 0; if (!Read(cursor, bits)) return -1; cursor += 8; double value = 0; std::memcpy(&value, &bits, 8); if (!appendFormatted(spec, value)) return -1; continue; }
		if (longLong) { std::uint64_t value = 0; if (!Read(cursor, value)) return -1; cursor += 8; if (!appendFormatted(spec, value)) return -1; }
		else { std::uint32_t value = 0; if (!readArg32(value)) return -1; if (!appendFormatted(spec, value)) return -1; }
	}
	return -1;
}

void CxbxUwpKernelBridge::FinishFastcall(std::uint32_t stackArgumentCount)
{
	FinishStdcall(stackArgumentCount);
}

void CxbxUwpKernelBridge::SetReturn64(std::uint64_t value)
{
	m_regs->eax = static_cast<std::uint32_t>(value);
	m_regs->edx = static_cast<std::uint32_t>(value >> 32);
}

void CxbxUwpKernelBridge::LogOrdinal(const char* operation, std::uint32_t ordinal) const
{
	if (!m_logger) return;
	char line[180] = {};
	sprintf_s(line, "[uwp-kernel] %s ordinal %u (0x%04X).\r\n", operation, ordinal, ordinal);
	m_logger(line);
}

void CxbxUwpKernelBridge::LogUnknownControl(bool deviceControl, std::uint32_t code,
	std::uint32_t input, std::uint32_t inputLength, std::uint32_t outputLength,
	const ObjectPtr& object)
{
	if (!m_logger) return;
	const std::uint64_t key = (static_cast<std::uint64_t>(deviceControl ? 1u : 2u) << 32) | code;
	const std::uint32_t count = ++m_unknownControls[key];
	// Keep long test sessions readable while retaining recurrence information.
	if (count > 4 && (count & (count - 1)) != 0) return;
	const bool optical = object && !m_gameRoot.empty() && object->path.compare(0, m_gameRoot.size(), m_gameRoot) == 0;
	const char* target = optical ? "dvd" : object && object->kind == ObjectKind::Directory ? "directory" : "data";
	char sample[33] = {};
	const std::uint32_t bytes = (std::min)(inputLength, 16u);
	if (bytes && IsRangeValid(input, bytes)) {
		for (std::uint32_t index = 0; index < bytes; ++index) { std::uint8_t byte = 0; Read(input + index, byte); sprintf_s(sample + index * 2, sizeof(sample) - index * 2, "%02X", byte); }
	}
	char line[420] = {};
	const std::uint32_t deviceType = code >> 16;
	const std::uint32_t access = (code >> 14) & 3;
	const std::uint32_t function = (code >> 2) & 0xFFF;
	const std::uint32_t method = code & 3;
	sprintf_s(line, "[uwp-io:unknown] {\"title\":\"%08X\",\"kind\":\"%s\",\"code\":\"%08X\",\"deviceType\":%u,\"function\":%u,\"method\":%u,\"access\":%u,\"target\":\"%s\",\"inputLength\":%u,\"outputLength\":%u,\"sample\":\"%s\",\"count\":%u}\r\n",
		m_titleId, deviceControl ? "IOCTL" : "FSCTL", code, deviceType, function, method, access, target, inputLength, outputLength, sample, count);
	m_logger(line);
}

HRESULT CxbxUwpKernelBridge::Install(std::uint32_t encodedThunkAddress, std::uint32_t consoleType,
	std::uint32_t imageEndAddress)
{
	if (!m_cpu || !m_ram || imageEndAddress >= DataBase) return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
	const bool debugXbe = consoleType == 2u;
	const std::uint32_t thunkXor = consoleType == 2u ? DebugThunkXor :
		(consoleType == 3u ? ChihiroThunkXor : RetailThunkXor);
	const std::uint32_t thunkAddress = encodedThunkAddress ^ thunkXor;
	if (!IsRangeValid(thunkAddress, sizeof(std::uint32_t))) return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);

	m_poolCursor = ((std::max)(imageEndAddress, 0x01000000u) + 0xFFFFu) & ~0xFFFFu;
	m_poolLimit = DataBase;
	m_imageEndAddress = imageEndAddress;
	{
		std::lock_guard<std::mutex> lock(m_memoryMutex);
		SetPageRange(0x03FE0000u, 0x10000u, XboxMemCommit, PAGE_READWRITE);
	}
	m_currentThread = Allocate(0x140);
	m_uniqueProcess = Allocate(0x1C);
	if (!m_currentThread || !m_uniqueProcess) return E_OUTOFMEMORY;
	InitializeGuestThreadBody(m_currentThread);
	Write(m_currentThread + 0x70, static_cast<std::uint8_t>(8));
	std::memset(m_ram + m_uniqueProcess, 0, 0x1C);
	Write(m_uniqueProcess, m_uniqueProcess); Write(m_uniqueProcess + 4, m_uniqueProcess);
	Write(m_uniqueProcess + 8, m_uniqueProcess + 8); Write(m_uniqueProcess + 12, m_uniqueProcess + 8);
	Write(m_uniqueProcess + 0x14, 60u); Write(m_uniqueProcess + 0x18, static_cast<std::int8_t>(8));
	std::memset(m_ram + DataBase, 0, StubBase - DataBase);
	std::memset(m_ram + StubBase, 0xCC, (CryptoRomLastOrdinal + 1) * StubStride);
	for (std::uint32_t ordinal = 0; ordinal <= MaxOrdinal; ++ordinal) {
		m_ram[StubBase + ordinal * StubStride] = 0xC3;
	}
	m_ram[StubBase + ExceptionReturnOrdinal * StubStride] = 0xC3;
	if (!LC86_SUCCESS(hook_add(m_cpu, StubBase + ExceptionReturnOrdinal * StubStride,
		HookTable[ExceptionReturnOrdinal]))) return E_FAIL;
	for (std::uint32_t ordinal : { ThreadReturnOrdinal, ApcReturnOrdinal, DpcReturnOrdinal,
		InterruptReturnOrdinal, SynchronizeReturnOrdinal, DriverReturnOrdinal, ThreadNotifyReturnOrdinal,
		UnwindReturnOrdinal, TlsReturnOrdinal, ShutdownReturnOrdinal }) {
		m_ram[StubBase + ordinal * StubStride] = 0xC3;
		if (!LC86_SUCCESS(hook_add(m_cpu, StubBase + ordinal * StubStride, HookTable[ordinal]))) return E_FAIL;
	}
	for (std::uint32_t ordinal = CryptoRomBaseOrdinal; ordinal <= CryptoRomLastOrdinal; ++ordinal) {
		m_ram[StubBase + ordinal * StubStride] = 0xC3;
		if (!LC86_SUCCESS(hook_add(m_cpu, StubBase + ordinal * StubStride, HookTable[ordinal]))) return E_FAIL;
	}

	InitializeExportedData(debugXbe);

	std::uint32_t imports = 0;
	for (std::uint32_t index = 0; index < 4096; ++index) {
		std::uint32_t entry = 0;
		const std::uint32_t slot = thunkAddress + index * 4;
		if (!Read(slot, entry)) return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
		if (entry == 0) break;
		const std::uint32_t ordinal = entry & 0x7FFFFFFFu;
		if (ordinal == 0 || ordinal > MaxOrdinal) return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);

		if (IsDataExport(ordinal)) {
			const std::uint32_t dataAddress = DataAddress(ordinal);
			Write(slot, dataAddress);
		} else {
			const std::uint32_t stubAddress = StubBase + ordinal * StubStride;
			Write(slot, stubAddress);
			if (!LC86_SUCCESS(hook_add(m_cpu, stubAddress, HookTable[ordinal]))) return E_FAIL;
		}
		++imports;
	}
	if (imports == 0) return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
	{ std::lock_guard<std::mutex> producerLock(g_activeBridgeMutex); g_activeBridge.store(this, std::memory_order_release); }
	LogOrdinal("thunks instalados; ultimo", imports);
	return S_OK;
}

void CxbxUwpKernelBridge::InitializeExportedData(bool debugXbe)
{
	struct GuestObjectType
	{
		std::uint32_t allocateProcedure, freeProcedure, closeProcedure, deleteProcedure;
		std::uint32_t parseProcedure, defaultObject, poolTag;
	};
	const std::uint32_t allocate = StubBase + 14 * StubStride;
	const std::uint32_t release = StubBase + 17 * StubStride;
	const std::uint32_t defaultObject = KernelGlobalsBase;
	std::memset(m_ram + KernelGlobalsBase, 0, StubBase - KernelGlobalsBase);
	InitializeDispatcher(defaultObject, 0, 0);
	auto objectType = [this, allocate, release, defaultObject](std::uint32_t ordinal,
		std::uint32_t bodyOffset, std::uint32_t tag, bool useDefault) {
		const GuestObjectType type = { allocate, release, 0, 0, 0,
			useDefault ? defaultObject : bodyOffset, tag };
		Write(DataAddress(ordinal), type);
	};
	objectType(16, 0, 0x76657645u, false);  // Evev / Event
	objectType(22, 0, 0x6174754Du, false);  // Muta / Mutant
	objectType(30, 0, 0x616D6553u, false);  // Sema / Semaphore
	objectType(31, 0, 0x656D6954u, false);  // Time / Timer
	objectType(64, 0, 0x706D6F43u, true);   // Comp / Completion
	objectType(70, 0, 0x69766544u, true);   // Devi / Device
	objectType(71, 0x20, 0x656C6946u, false); // File
	objectType(240, 0, 0x65726944u, true);  // Dire / Directory
	objectType(249, 0, 0x626D7953u, true);  // Symb / Symbolic link
	objectType(259, 0, 0x65726854u, false); // Thre / Thread

	Write(DataAddress(40), 3u);
	auto ansiPointer = [this](std::uint32_t ordinal, const char* value) {
		const std::uint32_t descriptor = DataAddress(ordinal) + 0x20;
		const std::uint32_t buffer = DataAddress(ordinal) + 0x40;
		const std::uint16_t length = static_cast<std::uint16_t>(std::strlen(value));
		Write(DataAddress(ordinal), descriptor);
		Write(descriptor, length); Write(descriptor + 2, static_cast<std::uint16_t>(length + 1));
		Write(descriptor + 4, buffer);
		std::memcpy(m_ram + buffer, value, length + 1);
	};
	ansiPointer(41, "CXBXR UWP VIRTUAL DISK");
	ansiPointer(42, "CXBXR000000000001");
	Write(DataAddress(88), static_cast<std::uint8_t>(debugXbe ? 1 : 0));
	Write(DataAddress(89), static_cast<std::uint8_t>(debugXbe ? 0 : 1));

	// MMGLOBALDATA points at stable guest-side counters.  Consumers can inspect
	// the data just as they do on the retail kernel; the bridge refreshes the
	// counters at every scheduling boundary.
	const std::uint32_t availablePages = KernelGlobalsBase + 0x100;
	const std::uint32_t allocatedByUsage = KernelGlobalsBase + 0x120;
	const std::uint32_t addressSpaceLock = KernelGlobalsBase + 0x180;
	const std::uint32_t vadRoot = KernelGlobalsBase + 0x1C0;
	const std::uint32_t mmGlobal[8] = { 0, 0, availablePages, allocatedByUsage,
		addressSpaceLock, vadRoot, vadRoot + 4, vadRoot + 8 };
	std::memcpy(m_ram + DataAddress(102), mmGlobal, sizeof(mmGlobal));

	const std::uint32_t launchPage = KernelGlobalsBase + 0x1000;
	std::memset(m_ram + launchPage, 0, 4096);
	Write(launchPage + 4, m_titleId);
	const char* launchPath = m_xiso ? "\\Device\\CdRom0\\default.xbe" : "D:\\default.xbe";
	std::memcpy(m_ram + launchPage + 8, launchPath, std::strlen(launchPath) + 1);
	Write(DataAddress(164), launchPage);

	const std::uint32_t fileNameBuffer = KernelGlobalsBase + 0x3000;
	const std::uint16_t fileNameLength = static_cast<std::uint16_t>(std::strlen(launchPath));
	Write(DataAddress(326), fileNameLength);
	Write(DataAddress(326) + 2, static_cast<std::uint16_t>(fileNameLength + 1));
	Write(DataAddress(326) + 4, fileNameBuffer);
	std::memcpy(m_ram + fileNameBuffer, launchPath, fileNameLength + 1);

	// Retail 5838 kernel and revision data.  The key exports are deliberately
	// stable per process and occupy their complete ABI sizes (16, 256 and 284
	// bytes respectively), with no overlap between exports.
	const std::uint16_t version[4] = { 1, 0, 5838, 1 };
	std::memcpy(m_ram + DataAddress(324), version, sizeof(version));
	const std::uint32_t hardwareFlags = 0xC0000031u;
	Write(DataAddress(322), hardwareFlags);
	Write(DataAddress(322) + 4, static_cast<std::uint8_t>(0xD3));
	Write(DataAddress(322) + 5, static_cast<std::uint8_t>(0xB2));
	const auto& publicKey = debugXbe ? CxbxUwpDebugPublicKey : CxbxUwpRetailPublicKey;
	std::memcpy(m_ram + DataAddress(355), publicKey.data(), publicKey.size());
	auto deriveConsoleKey = [this](const char* label, std::uint32_t ordinal) {
		SHA1_CTX sha = {}; std::uint8_t digest[20] = {};
		SHA1Init(&sha); SHA1Update(&sha, CxbxUwpRetailPublicKey.data(), static_cast<std::uint32_t>(CxbxUwpRetailPublicKey.size()));
		SHA1Update(&sha, reinterpret_cast<const std::uint8_t*>(label), static_cast<std::uint32_t>(std::strlen(label)));
		SHA1Final(digest, &sha); std::memcpy(m_ram + DataAddress(ordinal), digest, 16);
	};
	deriveConsoleKey("Cxbx-Reloaded UWP EEPROM key", 321);
	deriveConsoleKey("Cxbx-Reloaded UWP hard disk key", 323);
	auto deriveTitleKey = [](const std::uint8_t* input, std::uint8_t* output) {
		std::uint8_t innerPad[64], outerPad[64], innerDigest[20];
		std::memset(innerPad, 0x36, sizeof(innerPad));
		std::memset(outerPad, 0x5C, sizeof(outerPad));
		// The legacy kernel's certificate key defaults to sixteen zero bytes;
		// retain that retail-compatible derivation while consuming the actual
		// per-title material from the XBE certificate.
		SHA1_CTX sha = {}; SHA1Init(&sha); SHA1Update(&sha, innerPad, sizeof(innerPad)); SHA1Update(&sha, input, 16); SHA1Final(innerDigest, &sha);
		SHA1Init(&sha); SHA1Update(&sha, outerPad, sizeof(outerPad)); SHA1Update(&sha, innerDigest, sizeof(innerDigest));
		std::uint8_t digest[20]; SHA1Final(digest, &sha); std::memcpy(output, digest, 16);
	};
	deriveTitleKey(m_certificateLanKey.data(), m_ram + DataAddress(353));
	deriveTitleKey(m_certificateSignatureKey.data(), m_ram + DataAddress(325));
	for (std::size_t index = 0; index < 16; ++index) deriveTitleKey(
		m_certificateAlternateKeys.data() + index * 16, m_ram + DataAddress(354) + index * 16);
	Write(DataAddress(356), 1u);
	// IDE_CHANNEL_OBJECT is exported as writable kernel data. Establish the
	// embedded KDEVICE_QUEUE, two KDPCs, timer and interrupt dispatcher links
	// even though host storage is brokered rather than driven by ATA DMA.
	const std::uint32_t ide = DataAddress(357);
	std::memset(m_ram + ide, 0, 0x108);
	Write(ide + 24, static_cast<std::uint8_t>(4)); // IDE interrupt IRQL
	Write(ide + 30, static_cast<std::uint8_t>(3)); // retry limit
	Write(ide + 36, static_cast<std::int16_t>(4)); Write(ide + 38, static_cast<std::uint8_t>(4));
	Write(ide + 44, ide + 44); Write(ide + 48, ide + 44);
	for (const std::uint32_t dpc : { ide + 56, ide + 84 }) {
		Write(dpc, static_cast<std::int16_t>(0x13)); Write(dpc + 4, dpc + 4); Write(dpc + 8, dpc + 4);
	}
	InitializeDispatcher(ide + 112, 8, 0);
	auto createPermanentDirectory = [this](const wchar_t* name) {
		auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::Directory; object->objectType = DataAddress(240);
		object->path = name; object->permanent = true; object->references = 1;
		if (EnsureGuestObjectBody(object)) {
			object->attached = true;
			std::uint32_t flags = 0; Read(object->allocationBase + 12, flags); Write(object->allocationBase + 12, flags | 4u);
			m_namedObjects[NormalizeObjectName(object->path)] = object;
		}
	};
	createPermanentDirectory(L"\\"); createPermanentDirectory(L"\\Device");
	createPermanentDirectory(L"\\??"); createPermanentDirectory(L"\\Win32NamedObjects");

	m_kernelBootTime = std::chrono::steady_clock::now();
	m_lastExportedTick = 0;
	SyncExportedHandleTable();
	UpdateExportedData();
}

void CxbxUwpKernelBridge::UpdateExportedData()
{
	const auto elapsed = std::chrono::steady_clock::now() - m_kernelBootTime;
	const std::uint64_t interruptTime = static_cast<std::uint64_t>(
		std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count() / 100);
	const std::uint32_t tick = static_cast<std::uint32_t>(interruptTime / 10000u);
	auto writeSystemTime = [this](std::uint32_t address, std::uint64_t value) {
		const std::uint32_t low = static_cast<std::uint32_t>(value);
		const std::uint32_t high = static_cast<std::uint32_t>(value >> 32);
		// Xbox KSYSTEM_TIME uses High2/Low/High1 ordering to permit a stable
		// lock-free reader.  Write both high halves around the low half.
		Write(address + 8, high); Write(address, low); Write(address + 4, high);
	};
	writeSystemTime(DataAddress(120), interruptTime);
	FILETIME now = {}; GetSystemTimeAsFileTime(&now);
	const std::uint64_t systemTime = ((static_cast<std::uint64_t>(now.dwHighDateTime) << 32) |
		now.dwLowDateTime) + m_systemTimeOffset;
	writeSystemTime(DataAddress(154), systemTime);
	Write(DataAddress(156), tick);
	Write(DataAddress(157), 0x2710u);
	m_lastExportedTick = tick;

	std::uint32_t committedPages = 0;
	{
		std::lock_guard<std::mutex> lock(m_memoryMutex);
		for (const auto& allocation : m_allocations) committedPages += (allocation.second + 4095u) >> 12;
	}
	Write(KernelGlobalsBase + 0x100,
		(64u * 1024u * 1024u / 4096u) - (std::min)(committedPages, 64u * 1024u * 1024u / 4096u));
}

void CxbxUwpKernelBridge::SyncExportedHandleTable()
{
	const std::uint32_t table = DataAddress(245);
	const std::uint32_t root = table + 16;
	const std::uint32_t contents = KernelGlobalsBase + 0x4000;
	std::memset(m_ram + contents, 0, 8 * 64 * sizeof(std::uint32_t));
	std::uint32_t count = 0;
	{
		std::lock_guard<std::mutex> lock(m_objectMutex);
		count = static_cast<std::uint32_t>(m_handles.size());
		for (const auto& entry : m_handles) {
			const std::uint32_t index = entry.first >> 2;
			if (index < 8 * 64) Write(contents + index * 4, entry.second->guestAddress);
		}
	}
	Write(table, count); Write(table + 4, 0xFFFFFFFFu); Write(table + 8, m_nextHandle); Write(table + 12, root);
	for (std::uint32_t index = 0; index < 8; ++index) Write(root + index * 4, contents + index * 64 * 4);
}

HRESULT CxbxUwpKernelBridge::InitializeTls(std::uint32_t tlsDirectoryAddress,
	std::uint32_t stackBase)
{
	m_tlsDirectory = {};
	m_tlsCallbacks.clear();
	if (tlsDirectoryAddress && (!Read(tlsDirectoryAddress, m_tlsDirectory) ||
		m_tlsDirectory.end < m_tlsDirectory.start ||
		!IsRangeValid(m_tlsDirectory.start, m_tlsDirectory.end - m_tlsDirectory.start) ||
		(m_tlsDirectory.index && !IsRangeValid(m_tlsDirectory.index, sizeof(std::uint32_t))))) {
		return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
	}
	const std::uint32_t rawSize = m_tlsDirectory.end - m_tlsDirectory.start;
	if (m_tlsDirectory.zeroFill > 16u * 1024 * 1024 ||
		rawSize > 16u * 1024 * 1024 - m_tlsDirectory.zeroFill) {
		return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
	}
	if (m_tlsDirectory.callbacks) {
		if (!IsRangeValid(m_tlsDirectory.callbacks, 1)) return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
		m_tlsCallbacks.push_back(m_tlsDirectory.callbacks);
	}
	std::uint32_t rootPcr = 0, rootTlsVector = 0, rootTlsData = 0;
	HRESULT result = InitializeThreadTls(*m_regs, stackBase,
		rootPcr, rootTlsVector, rootTlsData);
	if (FAILED(result)) return result;
	// The XBE entry point executes as the root guest thread. Give it the same
	// termination trampoline as threads created through PsCreateSystemThread;
	// otherwise a normal RET consumes the zeroed top of stack and jumps to 0.
	if (m_regs->esp < sizeof(std::uint32_t)) return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
	m_regs->esp -= sizeof(std::uint32_t);
	if (!Write(m_regs->esp, StubBase + ThreadReturnOrdinal * StubStride)) {
		return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
	}
	ThreadContext root = {};
	root.id = m_nextThreadId++;
	root.guestThread = m_currentThread;
	root.regs = *m_regs;
	root.tib = rootPcr;
	root.tlsVector = rootTlsVector;
	root.tlsData = rootTlsData;
	root.state = ThreadState::Running;
	m_threads.clear();
	m_threads.push_back(root);
	m_currentThreadIndex = 0;
	auto rootObject = std::make_shared<KernelObject>();
	rootObject->kind = ObjectKind::Thread; rootObject->guestAddress = m_currentThread;
	rootObject->threadId = root.id; rootObject->objectType = DataAddress(259); rootObject->manualReset = true; rootObject->permanent = true;
	{ std::lock_guard<std::mutex> lock(m_objectMutex); m_guestObjects[m_currentThread] = rootObject; m_dispatcherObjects[m_currentThread] = rootObject; }
	m_threads.front().uniqueThread = CreateHandle(rootObject);
	Write(m_currentThread + 0x10, m_currentThread + 0x10); Write(m_currentThread + 0x14, m_currentThread + 0x10);
	Write(m_currentThread + 0x1C, stackBase); std::uint32_t rootStackLimit = 0; Read(root.tib + 8, rootStackLimit);
	Write(m_currentThread + 0x20, rootStackLimit); Write(m_currentThread + 0x24, m_regs->esp);
	Write(m_currentThread + 0x28, root.tlsVector);
	Write(m_currentThread + 0x2C, static_cast<std::uint8_t>(2));
	Write(m_currentThread + 0x32, root.priority);
	Write(m_currentThread + 0x34, m_currentThread + 0x34); Write(m_currentThread + 0x38, m_currentThread + 0x34);
	Write(m_currentThread + 0x3C, m_currentThread + 0x3C); Write(m_currentThread + 0x40, m_currentThread + 0x3C);
	Write(m_currentThread + 0x44, m_uniqueProcess);
	Write(m_currentThread + 0x4B, static_cast<std::uint8_t>(1));
	Write(m_currentThread + 0x68, 0u);
	Write(m_currentThread + 0x6C, 60u);
	Write(m_currentThread + 0x70, root.basePriority);
	Write(m_currentThread + 0x78, 0u); Write(m_currentThread + 0x7C, m_currentThread + 0x7C); Write(m_currentThread + 0x80, m_currentThread + 0x7C);
	const std::uint32_t rootThreadEntry = m_currentThread + 0x104;
	const std::uint32_t processThreadHead = m_uniqueProcess + 8;
	Write(rootThreadEntry, processThreadHead); Write(rootThreadEntry + 4, processThreadHead);
	Write(processThreadHead, rootThreadEntry); Write(processThreadHead + 4, rootThreadEntry);
	Write(m_uniqueProcess + 0x10, 1u);
	Write(m_currentThread + 0x12C, m_threads.front().uniqueThread);
	Write(m_currentThread + 0x134, m_currentThread + 0x134); Write(m_currentThread + 0x138, m_currentThread + 0x134);
	SyncProcessorControlRegion(m_threads.front());
	if (StartTlsCallbacks(m_threads.front(), 1)) *m_regs = m_threads.front().regs;
	return S_OK;
}

HRESULT CxbxUwpKernelBridge::InitializeThreadTls(regs_t& registers, std::uint32_t stackBase,
	std::uint32_t& pcr, std::uint32_t& tlsVector, std::uint32_t& tlsData,
	std::uint32_t stackSize, std::uint32_t requestedTlsDataSize)
{
	const std::uint32_t rawSize = m_tlsDirectory.end - m_tlsDirectory.start;
	const std::uint32_t initializedSize = rawSize + m_tlsDirectory.zeroFill;
	const std::uint32_t allocationSize = (std::max)(1u,
		(std::max)(initializedSize, requestedTlsDataSize));
	tlsVector = Allocate(4);
	tlsData = Allocate(allocationSize);
	const bool createPcr = m_processorControlRegion == 0;
	if (createPcr) m_processorControlRegion = Allocate(0x280);
	pcr = m_processorControlRegion;
	if (!tlsVector || !tlsData || !pcr) {
		if (tlsVector) Free(tlsVector); if (tlsData) Free(tlsData);
		if (createPcr && pcr) { Free(pcr); m_processorControlRegion = 0; }
		pcr = tlsVector = tlsData = 0; return E_OUTOFMEMORY;
	}
	std::memset(m_ram + tlsData, 0, allocationSize);
	if (rawSize) std::memcpy(m_ram + tlsData, m_ram + m_tlsDirectory.start, rawSize);
	Write(tlsVector, tlsData);
	if (m_tlsDirectory.index) { const std::uint32_t index = 0; Write(m_tlsDirectory.index, index); }
	const std::uint32_t stackLimit = stackBase > stackSize ? stackBase - stackSize : 0;
	if (createPcr) {
		std::memset(m_ram + pcr, 0, 0x280);
		Write(pcr + 0x00, 0xFFFFFFFFu);
		Write(pcr + 0x04, stackBase); Write(pcr + 0x08, stackLimit);
		Write(pcr + 0x18, pcr); // NT_TIB.Self
		Write(pcr + 0x1C, pcr); // KPCR.SelfPcr
		Write(pcr + 0x20, pcr + 0x28); // KPCR.Prcb
		Write(pcr + 0x24, m_currentIrql);
		Write(pcr + 0x50, pcr + 0x50); Write(pcr + 0x54, pcr + 0x50);
	}
	registers.fs = 0x3B;
	registers.fs_hidden.base = pcr;
	registers.fs_hidden.limit = 0x27F;
	registers.fs_hidden.flags = 1u << 22;
	if (m_logger) {
		char line[220] = {};
		sprintf_s(line, "[uwp-kernel] TLS inicializado: TIB=0x%08X vetor=0x%08X dados=0x%08X (%u+%u bytes).\r\n",
			pcr, tlsVector, tlsData, rawSize, m_tlsDirectory.zeroFill);
		m_logger(line);
	}
	return S_OK;
}

void CxbxUwpKernelBridge::SyncProcessorControlRegion(ThreadContext& thread)
{
	if (!thread.tib || !IsRangeValid(thread.tib, 0x280)) return;
	std::uint32_t stackBase = 0, stackLimit = 0;
	Read(thread.guestThread + 0x1C, stackBase); Read(thread.guestThread + 0x20, stackLimit);
	Write(thread.tib + 0x00, thread.exceptionList);
	Write(thread.tib + 0x04, stackBase); Write(thread.tib + 0x08, stackLimit);
	Write(thread.tib + 0x24, m_currentIrql);
	Write(thread.tib + 0x28, thread.guestThread);
	Write(thread.tib + 0x2C, 0u);
	Write(thread.tib + 0x30, m_threads.empty() ? thread.guestThread : m_threads.front().guestThread);
	Write(thread.tib + 0x58, m_dpcActive ? 1u : 0u);
}

void CxbxUwpKernelBridge::SetCurrentIrql(std::uint8_t irql)
{
	m_currentIrql = static_cast<std::uint8_t>((std::min)(static_cast<std::uint32_t>(irql), 31u));
	if (m_currentThreadIndex < m_threads.size()) SyncProcessorControlRegion(m_threads[m_currentThreadIndex]);
}

bool CxbxUwpKernelBridge::StartTlsCallbacks(ThreadContext& thread, std::uint32_t reason)
{
	if (m_tlsCallbacks.empty() || thread.tlsCallbacksActive) return false;
	thread.tlsResume = thread.regs;
	thread.tlsCallbackIndex = 0;
	thread.tlsCallbackReason = reason;
	thread.tlsCallbacksActive = true;
	return ContinueTlsCallbacks(thread);
}

bool CxbxUwpKernelBridge::ContinueTlsCallbacks(ThreadContext& thread)
{
	while (thread.tlsCallbackIndex < m_tlsCallbacks.size()) {
		const std::uint32_t callback = m_tlsCallbacks[thread.tlsCallbackIndex++];
		if (!callback || !IsRangeValid(callback, 1)) continue;
		thread.regs = thread.tlsResume;
		auto push = [this, &thread](std::uint32_t value) { thread.regs.esp -= 4; Write(thread.regs.esp, value); };
		push(0); push(thread.tlsCallbackReason); push(0x00010000u);
		push(StubBase + TlsReturnOrdinal * StubStride);
		thread.regs.eip = callback;
		return true;
	}
	thread.regs = thread.tlsResume;
	thread.tlsCallbacksActive = false;
	thread.tlsCallbackIndex = 0;
	return false;
}

std::uint32_t CxbxUwpKernelBridge::Allocate(std::uint32_t size)
{
	return AllocateAligned(size, 16, 0, m_poolLimit, PAGE_READWRITE);
}

std::uint32_t CxbxUwpKernelBridge::AllocateAligned(std::uint32_t size,
	std::uint32_t alignment, std::uint32_t lowest, std::uint32_t highest, std::uint32_t protect)
{
	if (!size) size = 1;
	if (!alignment) alignment = 1;
	if ((alignment & (alignment - 1)) != 0) return 0;
	if (size > (std::numeric_limits<std::uint32_t>::max)() - 15u) return 0;
	const std::uint32_t alignedSize = (size + 15u) & ~15u;
	highest = highest ? (std::min)(highest, m_poolLimit - 1) : m_poolLimit - 1;
	std::lock_guard<std::mutex> lock(m_memoryMutex);
	auto alignUp = [alignment](std::uint32_t value) { return (value + alignment - 1) & ~(alignment - 1); };
	std::uint32_t address = 0;
	for (auto it = m_freeAllocations.begin(); it != m_freeAllocations.end(); ++it) {
		const std::uint32_t start = alignUp((std::max)(it->first, lowest));
		const std::uint64_t end = static_cast<std::uint64_t>(start) + alignedSize;
		if (start >= it->first && end <= static_cast<std::uint64_t>(it->first) + it->second && end - 1 <= highest) {
			const std::uint32_t blockStart = it->first, blockEnd = it->first + it->second;
			m_freeAllocations.erase(it);
			if (start > blockStart) m_freeAllocations[blockStart] = start - blockStart;
			if (end < blockEnd) m_freeAllocations[static_cast<std::uint32_t>(end)] = blockEnd - static_cast<std::uint32_t>(end);
			address = start; break;
		}
	}
	if (!address) {
		address = alignUp((std::max)(m_poolCursor, lowest));
		if (address < m_poolCursor || static_cast<std::uint64_t>(address) + alignedSize > m_poolLimit ||
			static_cast<std::uint64_t>(address) + alignedSize - 1 > highest) return 0;
		if (address > m_poolCursor) m_freeAllocations[m_poolCursor] = address - m_poolCursor;
		m_poolCursor = address + alignedSize;
	}
	m_allocations[address] = alignedSize;
	m_allocationProtect[address] = protect;
	SetPageRange(address, alignedSize, XboxMemCommit, protect);
	std::memset(m_ram + address, 0, alignedSize);
	return address;
}

void CxbxUwpKernelBridge::Free(std::uint32_t address)
{
	std::lock_guard<std::mutex> lock(m_memoryMutex);
	auto allocated = m_allocations.find(address);
	if (allocated == m_allocations.end()) return;
	std::uint32_t start = allocated->first, size = allocated->second;
	m_allocations.erase(allocated);
	m_allocationProtect.erase(address);
	m_persistedAllocations.erase(address);
	for (std::uint32_t page = start & ~0xFFFu; page < start + size; page += 0x1000) {
		m_pageState.erase(page); m_pageProtect.erase(page); m_pageLockCount.erase(page);
	}
	auto next = m_freeAllocations.lower_bound(start);
	if (next != m_freeAllocations.begin()) {
		auto previous = std::prev(next);
		if (previous->first + previous->second == start) { start = previous->first; size += previous->second; m_freeAllocations.erase(previous); }
	}
	next = m_freeAllocations.lower_bound(start);
	if (next != m_freeAllocations.end() && start + size == next->first) { size += next->second; m_freeAllocations.erase(next); }
	if (start + size == m_poolCursor) {
		m_poolCursor = start;
		while (!m_freeAllocations.empty()) {
			auto tail = std::prev(m_freeAllocations.end());
			if (tail->first + tail->second != m_poolCursor) break;
			m_poolCursor = tail->first; m_freeAllocations.erase(tail);
		}
	} else m_freeAllocations[start] = size;
}

std::uint32_t CxbxUwpKernelBridge::AllocationSize(std::uint32_t address) const
{
	std::lock_guard<std::mutex> lock(m_memoryMutex);
	auto found = m_allocations.find(address);
	return found == m_allocations.end() ? 0 : found->second;
}

bool CxbxUwpKernelBridge::FindAllocation(std::uint32_t address,
	std::uint32_t& base, std::uint32_t& size) const
{
	std::lock_guard<std::mutex> lock(m_memoryMutex);
	for (const auto& allocation : m_allocations) {
		if (address >= allocation.first &&
			static_cast<std::uint64_t>(address) < static_cast<std::uint64_t>(allocation.first) + allocation.second) {
			base = allocation.first; size = allocation.second; return true;
		}
	}
	base = size = 0; return false;
}

void CxbxUwpKernelBridge::SetPageRange(std::uint32_t address, std::uint32_t size,
	std::uint32_t state, std::uint32_t protect)
{
	if (!size) return;
	const std::uint32_t first = address & ~0xFFFu;
	const std::uint64_t last = (static_cast<std::uint64_t>(address) + size + 0xFFFu) & ~0xFFFull;
	for (std::uint32_t page = first; page < last && page < XboxRamSize; page += 0x1000) {
		m_pageState[page] = state; m_pageProtect[page] = protect;
	}
}

bool CxbxUwpKernelBridge::IsAddressMapped(std::uint32_t address) const
{
	if (address < m_imageEndAddress) return true;
	if ((address >= DataBase && address < StubBase) ||
		(address >= StubBase && address < StubBase + (ShutdownReturnOrdinal + 1) * StubStride) ||
		(address >= KernelGlobalsBase && address < DataBase)) return true;
	std::lock_guard<std::mutex> lock(m_memoryMutex);
	const auto state = m_pageState.find(address & ~0xFFFu);
	return state != m_pageState.end() && state->second == XboxMemCommit;
}

std::uint32_t CxbxUwpKernelBridge::CreateHandle(ObjectPtr object)
{
	if (!object) return 0;
	if (!EnsureGuestObjectBody(object)) return 0;
	ObjectPtr retained = object;
	std::uint32_t handle = 0;
	{
		std::lock_guard<std::mutex> lock(m_objectMutex);
		while (!m_nextHandle || m_handles.count(m_nextHandle)) m_nextHandle += 4;
		handle = m_nextHandle;
		m_nextHandle += 4;
		m_handles.emplace(handle, std::move(object));
		if (retained->guestAddress) m_guestObjects[retained->guestAddress] = retained;
		// Xbox OBJECT_HEADER.PointerCount includes the reference owned by each
		// handle. Keep the host bookkeeping and the guest-visible header in lockstep.
		++retained->references;
		if (retained->allocationBase) Write(retained->allocationBase, retained->references);
		if (retained->guestAddress && (retained->kind == ObjectKind::Event || retained->kind == ObjectKind::Semaphore ||
			retained->kind == ObjectKind::Timer || retained->kind == ObjectKind::Mutant ||
			retained->kind == ObjectKind::Queue || retained->kind == ObjectKind::IoCompletion ||
			retained->kind == ObjectKind::Thread))
			m_dispatcherObjects[retained->guestAddress] = retained;
		// FILE_OBJECT contains a synchronization event at +0x38. Xbox drivers
		// routinely wait on this embedded event directly rather than on the handle.
		if ((retained->kind == ObjectKind::File || retained->kind == ObjectKind::Directory) &&
			retained->objectType == DataAddress(71))
			m_dispatcherObjects[retained->guestAddress + 0x38] = retained;
	}
	if (retained->allocationBase) { std::uint32_t count = 0; Read(retained->allocationBase + 4, count); Write(retained->allocationBase + 4, count + 1); }
	SyncExportedHandleTable();
	return handle;
}

std::uint32_t CxbxUwpKernelBridge::CreateOutputHandle(const ObjectPtr& object,
	std::uint32_t handleOut)
{
	if (!object || !IsRangeValid(handleOut, sizeof(std::uint32_t))) return StatusInvalidParameter;
	const std::uint32_t handle = CreateHandle(object);
	if (!handle) return StatusNoMemory;
	if (!Write(handleOut, handle)) {
		CloseGuestHandle(handle);
		return StatusInvalidParameter;
	}
	return StatusSuccess;
}

bool CxbxUwpKernelBridge::EnsureGuestObjectBody(const ObjectPtr& object)
{
	if (!object || object->guestAddress) return object != nullptr;
	std::uint32_t size = object->guestBodySize;
	if (!size) switch (object->kind) {
	case ObjectKind::File: size = 0x48; break;
	case ObjectKind::Event: size = 0x10; break;
	case ObjectKind::Semaphore: size = 0x14; break;
	case ObjectKind::Timer: size = 0x28; break;
	case ObjectKind::Mutant: size = 0x20; break;
	case ObjectKind::Queue:
	case ObjectKind::IoCompletion: size = 0x28; break;
	case ObjectKind::Directory: size = object->objectType == DataAddress(71) ? 0x48 : 44; break;
	case ObjectKind::SymbolicLink: size = 12; break;
	case ObjectKind::Thread: size = 0x160; break;
	default: return true;
	}
	const std::uint32_t alignedSize = (size + 3u) & ~3u;
	std::string leafName;
	if (!object->path.empty()) {
		const std::size_t separator = object->path.find_last_of(L"\\/");
		const std::wstring leaf = separator == std::wstring::npos ? object->path : object->path.substr(separator + 1);
		leafName.reserve(leaf.size());
		for (wchar_t character : leaf) leafName.push_back(static_cast<char>(character & 0xFF));
	}
	const bool named = !leafName.empty() || object->path == L"\\";
	const std::uint32_t nameInfoSize = named ? 16u : 0u;
	if (alignedSize > std::numeric_limits<std::uint32_t>::max() - 16u - nameInfoSize - leafName.size()) return false;
	const std::uint32_t storage = Allocate(nameInfoSize + 16u + alignedSize + static_cast<std::uint32_t>(leafName.size()));
	if (!storage) return false;
	const std::uint32_t header = storage + nameInfoSize;
	const std::uint32_t body = header + 16u;
	FillGuestMemory(storage, 0, nameInfoSize + 16u + alignedSize + leafName.size());
	object->allocationBase = header;
	object->bodyAllocation = storage;
	object->guestAddress = body;
	Write(header, object->references);
	Write(header + 4, 0u);
	Write(header + 8, object->objectType);
	Write(header + 12, static_cast<std::uint32_t>((named ? 1u : 0u) | (object->permanent ? 2u : 0u)));
	if (named) {
		const std::uint32_t nameBuffer = body + alignedSize;
		Write(storage, 0u); Write(storage + 4, 0u);
		Write(storage + 8, static_cast<std::uint16_t>(leafName.size()));
		Write(storage + 10, static_cast<std::uint16_t>(leafName.size()));
		Write(storage + 12, nameBuffer);
		if (auto* destination = GuestPointer(nameBuffer, leafName.size()))
			std::memcpy(destination, leafName.data(), leafName.size());
	}
	switch (object->kind) {
	case ObjectKind::Event:
		InitializeDispatcher(body, object->manualReset ? 0 : 1, object->signaled ? 1 : 0);
		break;
	case ObjectKind::Semaphore:
		InitializeDispatcher(body, 5, object->count);
		Write(body + 0x10, object->limit);
		break;
	case ObjectKind::Timer:
		InitializeDispatcher(body, object->manualReset ? 8 : 9, object->signaled ? 1 : 0);
		break;
	case ObjectKind::Mutant: {
		InitializeDispatcher(body, 2, object->signaled ? 1 : 0);
		Write(body + 0x10, body + 0x10); Write(body + 0x14, body + 0x10);
		ThreadContext* owner = nullptr;
		for (auto& thread : m_threads) if (thread.id == object->ownerThreadId) { owner = &thread; break; }
		Write(body + 0x18, owner ? owner->guestThread : 0u);
		Write(body + 0x1C, static_cast<std::uint8_t>(object->abandoned));
		if (owner) LinkMutantToThread(object, owner);
		break;
	}
	case ObjectKind::Queue:
	case ObjectKind::IoCompletion:
		InitializeDispatcher(body, 4, 0);
		Write(body + 0x10, body + 0x10); Write(body + 0x14, body + 0x10);
		Write(body + 0x18, 0u); Write(body + 0x1C, static_cast<std::int32_t>(object->limit));
		break;
	case ObjectKind::File:
	case ObjectKind::Directory:
		if (object->objectType != DataAddress(71)) break;
		Write(body, static_cast<std::int16_t>(5));
		Write(body + 2, static_cast<std::uint8_t>(((object->desiredAccess & (GENERIC_READ | 0x21u)) ? 2 : 0) |
			((object->desiredAccess & (GENERIC_WRITE | 0x106u)) ? 4 : 0) |
			((object->desiredAccess & DELETE) ? 8 : 0)));
		{
			std::uint8_t flags = 0x20;
			if (object->openOptions & (0x10u | 0x20u)) flags |= 0x01;
			if (object->openOptions & 0x10u) flags |= 0x02;
			if (object->openOptions & 0x08u) flags |= 0x04;
			if (object->openOptions & 0x04u) flags |= 0x08;
			if (object->openOptions & 0x800u) flags |= 0x40;
			Write(body + 3, flags);
			if (flags & 0x01) InitializeDispatcher(body + 0x28, 1, 0);
		}
		InitializeDispatcher(body + 0x38, 0, 0); object->signaled = false;
		break;
	default:
		break;
	}
	{
		std::lock_guard<std::mutex> lock(m_objectMutex);
		m_guestObjects[body] = object;
		if (object->kind == ObjectKind::Event || object->kind == ObjectKind::Semaphore ||
			object->kind == ObjectKind::Timer || object->kind == ObjectKind::Mutant ||
			object->kind == ObjectKind::Queue || object->kind == ObjectKind::IoCompletion)
			m_dispatcherObjects[body] = object;
	}
	return true;
}

std::uint32_t CxbxUwpKernelBridge::CreateNamedHandle(const ObjectPtr& object,
	std::uint32_t attributes, std::uint32_t handleOut)
{
	if (!object || !IsRangeValid(handleOut, 4)) return StatusInvalidParameter;
	Write(handleOut, 0u);
	if (attributes) {
		if (!IsRangeValid(attributes, 12)) return StatusInvalidParameter;
		std::uint32_t stringAddress = 0, flags = 0; Read(attributes + 4, stringAddress); Read(attributes + 8, flags);
		if (stringAddress) {
			std::wstring name;
			const std::uint32_t resolveStatus = ResolveObjectName(attributes, name);
			if (resolveStatus != StatusSuccess) return resolveStatus;
			const std::wstring key = NormalizeObjectName(name);
			auto existing = m_namedObjects.find(key);
			if (existing != m_namedObjects.end()) {
				if ((flags & 0x80u) == 0) return StatusObjectNameCollision;
				if (existing->second->kind != object->kind ||
					(existing->second->objectType && object->objectType && existing->second->objectType != object->objectType))
					return 0xC0000024u; // STATUS_OBJECT_TYPE_MISMATCH
				const std::uint32_t status = CreateOutputHandle(existing->second, handleOut);
				return status == StatusSuccess ? 0x40000000u : status;
			}
			const std::size_t separator = name.find_last_of(L'\\');
			const std::wstring parentName = separator == 0 ? L"\\" : name.substr(0, separator);
			auto parentObject = m_namedObjects.find(NormalizeObjectName(parentName));
			if (parentObject == m_namedObjects.end() || parentObject->second->kind != ObjectKind::Directory ||
				parentObject->second->objectType != DataAddress(240)) return 0xC000003Au;
			object->path = name; object->permanent = (flags & 0x10u) != 0; m_namedObjects[key] = object;
		}
	}
	if (!EnsureGuestObjectBody(object)) {
		if (!object->path.empty()) m_namedObjects.erase(NormalizeObjectName(object->path));
		return StatusNoMemory;
	}
	const std::uint32_t status = CreateOutputHandle(object, handleOut);
	if (status == StatusSuccess && !object->path.empty()) {
		object->attached = true;
		++object->references;
		if (object->allocationBase) {
			std::uint32_t flags = 0; Read(object->allocationBase + 12, flags);
			Write(object->allocationBase, object->references);
			Write(object->allocationBase + 12, flags | 4u);
		}
	} else if (status != StatusSuccess) {
		if (!object->path.empty()) m_namedObjects.erase(NormalizeObjectName(object->path));
		DereferenceObject(object, false);
	}
	return status;
}

CxbxUwpKernelBridge::ObjectPtr CxbxUwpKernelBridge::GetHandle(std::uint32_t handle) const
{
	std::lock_guard<std::mutex> lock(m_objectMutex);
	if (handle == 0xFFFFFFFDu || handle == 0xFFFFFFFCu) {
		const auto directory = m_namedObjects.find(handle == 0xFFFFFFFDu ? L"\\??" : L"\\WIN32NAMEDOBJECTS");
		return directory == m_namedObjects.end() ? nullptr : directory->second;
	}
	if (handle == 0xFFFFFFFEu && m_currentThreadIndex < m_threads.size()) {
		auto current = m_guestObjects.find(m_threads[m_currentThreadIndex].guestThread);
		return current == m_guestObjects.end() ? nullptr : current->second;
	}
	auto found = m_handles.find(handle);
	return found == m_handles.end() ? nullptr : found->second;
}

CxbxUwpKernelBridge::ObjectPtr CxbxUwpKernelBridge::GetDispatcherObject(std::uint32_t address)
{
	if (!address) return nullptr;
	{
		std::lock_guard<std::mutex> lock(m_objectMutex);
		auto found = m_dispatcherObjects.find(address);
		if (found != m_dispatcherObjects.end()) return found->second;
	}
	// Kernel and driver images contain statically initialized dispatcher
	// objects which never pass through the exported KeInitialize* routines.
	// Reconstruct the host-side bookkeeping from their Xbox DISPATCHER_HEADER.
	if (!IsRangeValid(address, 16)) return nullptr;
	std::uint8_t type = 0;
	std::int32_t signalState = 0;
	if (!Read(address, type) || !Read(address + 4, signalState)) return nullptr;
	auto object = std::make_shared<KernelObject>();
	object->guestAddress = address;
	object->signaled = signalState > 0;
	switch (type) {
	case 0: // NotificationEvent
	case 1: // SynchronizationEvent
		object->kind = ObjectKind::Event;
		object->manualReset = type == 0;
		break;
	case 2: { // Mutant
		object->kind = ObjectKind::Mutant;
		std::uint32_t owner = 0;
		Read(address + 0x18, owner);
		if (auto* ownerThread = FindThreadByGuestAddress(owner)) object->ownerThreadId = ownerThread->id;
		Read(address + 0x1C, object->abandoned);
		object->recursionCount = signalState <= 0 ? 1 - signalState : 0;
		break;
	}
	case 4: // Queue
		object->kind = ObjectKind::Queue;
		break;
	case 5: // Semaphore
		object->kind = ObjectKind::Semaphore;
		object->count = signalState;
		Read(address + 16, object->limit);
		break;
	case 8: // NotificationTimer
	case 9: // SynchronizationTimer
		object->kind = ObjectKind::Timer;
		object->manualReset = type == 8;
		break;
	default:
		return nullptr;
	}
	std::lock_guard<std::mutex> lock(m_objectMutex);
	auto inserted = m_dispatcherObjects.emplace(address, object);
	return inserted.second ? object : inserted.first->second;
}

std::uint32_t CxbxUwpKernelBridge::CloseGuestHandle(std::uint32_t handle)
{
	bool erased = false;
	bool detach = false;
	ObjectPtr object;
	{
		std::lock_guard<std::mutex> lock(m_objectMutex);
		auto found = m_handles.find(handle);
		if (found != m_handles.end()) { object = found->second; m_handles.erase(found); erased = true; }
	}
	if (object && object->allocationBase) {
		std::uint32_t handles = 0; Read(object->allocationBase + 4, handles);
		if (handles) --handles;
		Write(object->allocationBase + 4, handles);
		detach = handles == 0 && object->attached && !object->permanent;
	}
	if (object && detach) {
		if (!object->path.empty()) m_namedObjects.erase(NormalizeObjectName(object->path));
		object->attached = false;
		if (object->allocationBase) {
			std::uint32_t flags = 0; Read(object->allocationBase + 12, flags);
			Write(object->allocationBase + 12, flags & ~4u);
		}
		DereferenceObject(object, true); // release the directory attachment reference
	}
	if (object) DereferenceObject(object, true);
	if (erased) SyncExportedHandleTable();
	return erased ? StatusSuccess : StatusInvalidHandle;
}

void CxbxUwpKernelBridge::DereferenceObject(const ObjectPtr& object, bool decrement)
{
	if (!object) return;
	std::uint32_t allocation = 0;
	ObjectPtr releasedLinkTarget;
	{
		std::lock_guard<std::mutex> lock(m_objectMutex);
		if (decrement && object->references) --object->references;
		if (object->allocationBase) Write(object->allocationBase, object->references);
		bool hasHandle = false;
		for (const auto& handle : m_handles) if (handle.second.get() == object.get()) { hasHandle = true; break; }
		bool hasWaitReference = false;
		for (const auto& thread : m_threads) {
			if (std::any_of(thread.waitObjects.begin(), thread.waitObjects.end(), [&object](const ObjectPtr& waited) {
				return waited.get() == object.get();
			})) { hasWaitReference = true; break; }
		}
		if (object->references || hasHandle || hasWaitReference || object->permanent) return;
		for (auto it = m_namedObjects.begin(); it != m_namedObjects.end();) {
			if (it->second.get() == object.get()) it = m_namedObjects.erase(it); else ++it;
		}
		for (auto it = m_dispatcherObjects.begin(); it != m_dispatcherObjects.end();) {
			if (it->second.get() == object.get()) it = m_dispatcherObjects.erase(it); else ++it;
		}
		m_guestObjects.erase(object->guestAddress);
		if (object->kind == ObjectKind::SymbolicLink && object->linkTarget) {
			releasedLinkTarget = object->linkTarget;
			object->linkTarget.reset();
		}
		allocation = object->bodyAllocation ? object->bodyAllocation : object->allocationBase;
	}
	if (allocation) Free(allocation);
	if (releasedLinkTarget) DereferenceObject(releasedLinkTarget, true);
}

bool CxbxUwpKernelBridge::ReadObjectName(std::uint32_t attributesAddress,
	std::wstring& name, std::uint32_t& rootHandle) const
{
	std::uint32_t stringAddress = 0, attributes = 0;
	rootHandle = 0;
	if (!attributesAddress || !Read(attributesAddress, rootHandle) ||
		!Read(attributesAddress + 4, stringAddress) || !Read(attributesAddress + 8, attributes) ||
		!stringAddress) return false;
	std::uint16_t length = 0, maximum = 0;
	std::uint32_t buffer = 0;
	if (!Read(stringAddress, length) || !Read(stringAddress + 2, maximum) ||
		!Read(stringAddress + 4, buffer) || length > maximum || !IsRangeValid(buffer, length)) return false;
	name.clear();
	name.reserve(length);
	for (std::uint32_t i = 0; i < length; ++i) {
		std::uint8_t character = 0; if (!Read(buffer + i, character)) return false;
		name.push_back(static_cast<wchar_t>(character));
	}
	return true;
}

std::uint32_t CxbxUwpKernelBridge::ResolveObjectName(std::uint32_t attributesAddress,
	std::wstring& name, ObjectPtr* parent) const
{
	name.clear();
	if (parent) parent->reset();
	std::uint32_t rootHandle = 0;
	if (!ReadObjectName(attributesAddress, name, rootHandle) || name.empty()) return 0xC0000033u;
	std::replace(name.begin(), name.end(), L'/', L'\\');
	if ((name.size() > 1 && name.back() == L'\\') || name.find(L"\\\\") != std::wstring::npos) return 0xC0000033u;
	if (rootHandle) {
		if (name.front() == L'\\') return 0xC0000033u;
		auto root = GetHandle(rootHandle);
		if (!root) return StatusInvalidHandle;
		if (root->kind != ObjectKind::Directory || root->objectType != DataAddress(240)) return 0xC0000024u;
		if (parent) *parent = root;
		name = root->path == L"\\" ? L"\\" + name : root->path + L"\\" + name;
	} else if (name.front() != L'\\') {
		return 0xC0000033u;
	}
	return StatusSuccess;
}

bool CxbxUwpKernelBridge::ResolveGuestPath(std::uint32_t attributesAddress, std::wstring& path) const
{
	std::wstring guest;
	std::uint32_t rootHandle = 0;
	if (m_dataRoot.empty() || !ReadObjectName(attributesAddress, guest, rootHandle)) return false;
	std::wstring base = m_gameRoot.empty() ? m_dataRoot : m_gameRoot;
	// The Xbox object manager exposes the DOS-device directory as the pseudo
	// handle (HANDLE)-3.  It is not present in the process handle table: names
	// relative to it must be resolved as \??\<name> (for example Z:\).
	const bool dosDevicesRoot = rootHandle == 0xFFFFFFFDu;
	if (dosDevicesRoot) {
		while (!guest.empty() && (guest.front() == L'\\' || guest.front() == L'/')) guest.erase(guest.begin());
		guest = L"\\??\\" + guest;
		rootHandle = 0;
	}
	if (rootHandle) {
		auto root = GetHandle(rootHandle);
		if (!root || (root->kind != ObjectKind::Directory && root->kind != ObjectKind::File)) return false;
		base = root->path;
	}
	std::replace(guest.begin(), guest.end(), L'/', L'\\');
	if (!rootHandle) {
		// Resolve object-manager symbolic links before translating the Xbox device
		// namespace into brokered host roots. Chained links are bounded to reject
		// cycles while still supporting \??\D: -> \Device\CdRom0 style aliases.
		for (unsigned depth = 0; depth < 8; ++depth) {
			std::wstring lookup = guest; if (lookup.empty() || lookup.front() != L'\\') lookup.insert(lookup.begin(), L'\\');
			const std::wstring normalized = NormalizeObjectName(lookup);
			ObjectPtr link; std::size_t matched = 0;
			{
				std::lock_guard<std::mutex> lock(m_objectMutex);
				for (const auto& named : m_namedObjects) {
					if (named.second->kind != ObjectKind::SymbolicLink || named.first.size() <= matched ||
						normalized.size() < named.first.size() || normalized.compare(0, named.first.size(), named.first) != 0 ||
						(normalized.size() != named.first.size() && normalized[named.first.size()] != L'\\')) continue;
					link = named.second; matched = named.first.size();
				}
			}
			if (!link) break;
			guest = link->target + lookup.substr(matched);
			std::replace(guest.begin(), guest.end(), L'/', L'\\');
			if (depth == 7) return false;
		}
	}
	while (!guest.empty() && guest.front() == L'\\') guest.erase(guest.begin());
	if (guest.size() > 3 && guest.compare(0, 3, L"??\\") == 0) guest.erase(0, 3);
	const std::wstring cdrom = L"Device\\CdRom0";
	if (guest.size() >= cdrom.size() && _wcsnicmp(guest.c_str(), cdrom.c_str(), cdrom.size()) == 0) {
		base = m_gameRoot;
		guest.erase(0, cdrom.size());
		while (!guest.empty() && guest.front() == L'\\') guest.erase(guest.begin());
	}
	const std::wstring device = L"Device\\Harddisk0\\Partition";
	if (guest.size() >= device.size() && _wcsnicmp(guest.c_str(), device.c_str(), device.size()) == 0) {
		base = m_dataRoot;
		guest.erase(0, device.size());
		const auto slash = guest.find(L'\\');
		const std::wstring partition = guest.substr(0, slash);
		guest = L"Partition" + partition + (slash == std::wstring::npos ? L"" : guest.substr(slash));
	}
	const std::wstring memoryUnit = L"Device\\MemoryUnit";
	const std::wstring mu = L"Device\\Mu";
	if ((guest.size() >= memoryUnit.size() && _wcsnicmp(guest.c_str(), memoryUnit.c_str(), memoryUnit.size()) == 0) ||
		(guest.size() >= mu.size() && _wcsnicmp(guest.c_str(), mu.c_str(), mu.size()) == 0)) {
		const std::size_t prefix = guest.size() >= memoryUnit.size() && _wcsnicmp(guest.c_str(), memoryUnit.c_str(), memoryUnit.size()) == 0 ? memoryUnit.size() : mu.size();
		std::size_t end = prefix; while (end < guest.size() && std::iswdigit(guest[end])) ++end;
		const std::wstring unit = end == prefix ? L"0" : guest.substr(prefix, end - prefix);
		std::wstring units = m_dataRoot + L"\\MemoryUnits"; CreateDirectoryFromAppW(units.c_str(), nullptr);
		base = units + L"\\MU" + unit; CreateDirectoryFromAppW(base.c_str(), nullptr);
		guest.erase(0, end); while (!guest.empty() && guest.front() == L'\\') guest.erase(guest.begin());
	}
	else if (guest.size() >= 2 && guest[1] == L':') {
		const wchar_t drive = static_cast<wchar_t>(std::towupper(guest[0]));
		if (drive == L'D') {
			base = m_gameRoot;
			guest.erase(0, 2);
			while (!guest.empty() && guest.front() == L'\\') guest.erase(guest.begin());
		} else {
			base = m_dataRoot;
			guest[1] = L'\\';
		}
	}
	if (base.empty()) return false;
	std::wstring relative;
	std::size_t cursor = 0;
	while (cursor <= guest.size()) {
		const auto separator = guest.find(L'\\', cursor);
		const std::wstring component = guest.substr(cursor,
			separator == std::wstring::npos ? std::wstring::npos : separator - cursor);
		if (component == L"..") return false;
		if (!component.empty() && component != L".") {
			if (component.find_first_of(L"<>|\"?*") != std::wstring::npos) return false;
			if (!relative.empty()) relative.push_back(L'\\');
			relative += component;
		}
		if (separator == std::wstring::npos) break;
		cursor = separator + 1;
	}
	path = base;
	if (!relative.empty()) { path.push_back(L'\\'); path += relative; }
	return path.size() >= base.size() &&
		_wcsnicmp(path.c_str(), base.c_str(), base.size()) == 0 &&
		(path.size() == base.size() || path[base.size()] == L'\\');
}

bool CxbxUwpKernelBridge::GetXisoRelativePath(const std::wstring& path, std::string& relative) const
{
	if (!m_xiso || m_gameRoot.empty() || path.size() < m_gameRoot.size() ||
		_wcsnicmp(path.c_str(), m_gameRoot.c_str(), m_gameRoot.size()) != 0 ||
		(path.size() != m_gameRoot.size() && path[m_gameRoot.size()] != L'\\')) return false;
	relative.clear();
	std::size_t start = m_gameRoot.size();
	if (start < path.size() && path[start] == L'\\') ++start;
	for (std::size_t index = start; index < path.size(); ++index) {
		const wchar_t character = path[index];
		relative.push_back(character <= 0xFF ? static_cast<char>(character) : '?');
	}
	return true;
}

void CxbxUwpKernelBridge::WriteIoStatus(std::uint32_t address, std::uint32_t status,
	std::uint32_t information)
{
	if (!address) return;
	Write(address, status);
	Write(address + 4, information);
}

void CxbxUwpKernelBridge::SignalFileCompletion(const ObjectPtr& object, std::uint32_t status)
{
	if (!object || !object->guestAddress ||
		(object->kind != ObjectKind::File && object->kind != ObjectKind::Directory)) return;
	// FILE_OBJECT.FinalStatus and the embedded notification Event are observable
	// even for calls that complete synchronously in the UWP broker.
	Write(object->guestAddress + 0x10, status);
	object->signaled = true;
	SyncDispatcherSignal(object);
	m_objectChanged.notify_all();
}

void CxbxUwpKernelBridge::CompleteIrp(std::uint32_t irp)
{
	if (!IsRangeValid(irp, 0x60)) return;
	std::uint32_t iosb = 0, event = 0, status = 0, information = 0;
	Read(irp + 0x1C, iosb); Read(irp + 0x20, event);
	Read(irp + 0x10, status); Read(irp + 0x14, information);
	if (iosb && IsRangeValid(iosb, 8)) WriteIoStatus(iosb, status, information);
	if (event) {
		auto object = GetDispatcherObject(event);
		if (!object) {
			object = std::make_shared<KernelObject>(); object->kind = ObjectKind::Event;
			object->guestAddress = event; object->manualReset = true;
			std::lock_guard<std::mutex> lock(m_objectMutex); m_dispatcherObjects[event] = object;
		}
		object->signaled = true; Write(event + 4, 1u); m_objectChanged.notify_all();
	}
	// Remove Tail.Overlay.ListEntry from the owning thread's IRP list if it was queued.
	std::uint32_t next = 0, previous = 0;
	if (Read(irp + 0x50, next) && Read(irp + 0x54, previous) && next && previous &&
		IsRangeValid(next, 8) && IsRangeValid(previous, 8)) {
		Write(previous, next); Write(next + 4, previous);
	}
	Write(irp + 0x50, 0u); Write(irp + 0x54, 0u); Write(irp + 0x4C, 0u);
	// A FILE_OBJECT may route completed requests to an I/O completion port.
	std::uint32_t fileObject = 0, completionContext = 0;
	if (Read(irp + 0x5C, fileObject) && fileObject && IsRangeValid(fileObject + 0x20, 4) &&
		Read(fileObject + 0x20, completionContext) && completionContext && IsRangeValid(completionContext, 8)) {
		std::uint32_t port = 0, key = 0; Read(completionContext, port); Read(completionContext + 4, key);
		auto found = m_guestObjects.find(port);
		if (found != m_guestObjects.end() && found->second->kind == ObjectKind::IoCompletion) {
			found->second->completions.push_back({ key, irp, status, information });
			found->second->signaled = true; SyncDispatcherSignal(found->second); m_objectChanged.notify_all();
		}
	}
	Write(irp + 0x1A, static_cast<std::uint8_t>(0));
	WakeThreads(); SyncReadyList();
}

std::uint32_t CxbxUwpKernelBridge::StatusFromWin32(std::uint32_t error) const
{
	switch (error) {
	case ERROR_SUCCESS: return StatusSuccess;
	case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND: return StatusObjectNameNotFound;
	case ERROR_FILE_EXISTS: case ERROR_ALREADY_EXISTS: return StatusObjectNameCollision;
	case ERROR_ACCESS_DENIED: return StatusAccessDenied;
	case ERROR_INVALID_HANDLE: return StatusInvalidHandle;
	case ERROR_HANDLE_EOF: return StatusEndOfFile;
	default: return 0xC0000000u | (error & 0xFFFFu);
	}
}

std::uint32_t CxbxUwpKernelBridge::OpenGuestFile(std::uint32_t handleOut,
	std::uint32_t desiredAccess, std::uint32_t attributesAddress, std::uint32_t ioStatus,
	std::uint32_t shareAccess, std::uint32_t disposition, std::uint32_t options)
{
	std::wstring path;
	if (!handleOut || !ResolveGuestPath(attributesAddress, path)) return StatusInvalidParameter;
	const bool optical = !m_gameRoot.empty() && path.size() >= m_gameRoot.size() &&
		_wcsnicmp(path.c_str(), m_gameRoot.c_str(), m_gameRoot.size()) == 0 &&
		(path.size() == m_gameRoot.size() || path[m_gameRoot.size()] == L'\\');
	const bool opticalRoot = optical && path.size() == m_gameRoot.size();
	// A partition root can be opened either as a FATX directory or as a raw
	// block device. Keep raw sectors in a persistent broker-safe backing file;
	// directory opens and paths below the partition retain folder semantics.
	bool rawDevice = false;
	std::uint32_t partitionNumber = 0xFFFFFFFFu;
	if ((options & 1u) == 0 && !m_dataRoot.empty()) {
		for (unsigned partition = 0; partition <= 7; ++partition) {
			const std::wstring root = m_dataRoot + L"\\Partition" + std::to_wstring(partition);
			if (_wcsicmp(path.c_str(), root.c_str()) == 0) {
				rawDevice = true;
				partitionNumber = partition;
				break;
			}
		}
	}
	if (rawDevice) path += L"\\RawDevice.bin";
	std::string xisoPath;
	if (GetXisoRelativePath(path, xisoPath)) {
		// CDFS accepts a handle even when a title asks for write-attribute bits;
		// the media remains read-only because NtWriteFile/FSCTL mutations reject
		// every XISO-backed object. Reject only create/truncate dispositions here.
		if (disposition != 1) { WriteIoStatus(ioStatus, StatusAccessDenied, 0); return StatusAccessDenied; }
		CxbxUwpXisoEntry entry;
		const HRESULT findResult = m_xiso->Find(xisoPath, entry);
		if (FAILED(findResult)) { const auto status = StatusFromWin32(HRESULT_CODE(findResult)); WriteIoStatus(ioStatus, status, 0); return status; }
		const bool directory = (options & 1u) != 0;
		const bool volume = xisoPath.empty() && !directory;
		if (!volume && directory != entry.IsDirectory()) { WriteIoStatus(ioStatus, StatusInvalidParameter, 0); return StatusInvalidParameter; }
		if (volume) entry.attributes = 0;
		auto object = std::make_shared<KernelObject>();
		object->kind = directory ? ObjectKind::Directory : ObjectKind::File;
		object->objectType = DataAddress(71);
		object->path = path; object->xiso = true; object->xisoVolume = volume;
		object->xisoEntry = entry; object->signaled = false;
		object->desiredAccess = desiredAccess; object->openOptions = options;
		const auto handleStatus = CreateOutputHandle(object, handleOut);
		if (handleStatus != StatusSuccess) { WriteIoStatus(ioStatus, handleStatus, 0); return handleStatus; }
		WriteIoStatus(ioStatus, StatusSuccess, FileOpened);
		return StatusSuccess;
	}
	DWORD creation = OPEN_EXISTING;
	switch (disposition) {
	case 0: creation = CREATE_ALWAYS; break;
	case 1: creation = OPEN_EXISTING; break;
	case 2: creation = CREATE_NEW; break;
	case 3: creation = OPEN_ALWAYS; break;
	case 4: creation = TRUNCATE_EXISTING; break;
	case 5: creation = CREATE_ALWAYS; break;
	default: return StatusInvalidParameter;
	}
	// The physical disk exists before any title starts. OPEN_ALWAYS creates the
	// local sparse backing store on first use while preserving it on later runs.
	if (rawDevice) creation = OPEN_ALWAYS;
	const bool directory = (options & 1u) != 0;
	if (optical && disposition != 1) {
		WriteIoStatus(ioStatus, StatusAccessDenied, 0);
		return StatusAccessDenied;
	}
	if (directory && (disposition == 2 || disposition == 3 || disposition == 5)) {
		if (!CreateDirectoryFromAppW(path.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
			const auto status = StatusFromWin32(GetLastError()); WriteIoStatus(ioStatus, status, 0); return status;
		}
		creation = OPEN_EXISTING;
	}
	CREATEFILE2_EXTENDED_PARAMETERS parameters = { sizeof(parameters) };
	parameters.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
	// CdRom0 is a volume object to the guest but a brokered StorageFolder on the
	// host. Opening that root still needs BACKUP_SEMANTICS even when the guest did
	// not set FILE_DIRECTORY_FILE.
	parameters.dwFileFlags = (directory || opticalRoot) ? FILE_FLAG_BACKUP_SEMANTICS : 0;
	DWORD access = desiredAccess & (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL |
		DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE);
	if (desiredAccess & (0x00000001u | 0x00000008u | 0x00000080u)) access |= GENERIC_READ;
	if (desiredAccess & (0x00000002u | 0x00000004u | 0x00000010u | 0x00000100u)) access |= GENERIC_WRITE;
	if ((access & (GENERIC_READ | GENERIC_WRITE | GENERIC_ALL)) == 0) access |= GENERIC_READ;
	if (optical) {
		// D: and CdRom0 are read-only. Xbox callers commonly include write-
		// attributes or GENERIC_ALL while merely querying the volume; forwarding
		// those bits to CreateFile2FromApp makes the broker reject the folder.
		access &= ~(GENERIC_WRITE | GENERIC_ALL | DELETE | WRITE_DAC | WRITE_OWNER);
		access |= GENERIC_READ;
	}
	HANDLE native = CreateFile2FromAppW(path.c_str(), access, shareAccess & 7u, creation, &parameters);
	bool brokeredRoot = false;
	if (native == INVALID_HANDLE_VALUE && optical) {
		// FutureAccessList grants access to the StorageFolder object, not to an
		// arbitrary absolute Win32 path. Ask the UI-side broker to create a real
		// interoperable HANDLE relative to the retained StorageFolder.
		std::wstring relative = path.substr(m_gameRoot.size());
		while (!relative.empty() && (relative.front() == L'\\' || relative.front() == L'/')) relative.erase(relative.begin());
		const HRESULT brokerResult = CxbxUwpOpenBrokeredGameFile(relative.c_str(),
			directory || opticalRoot, access, shareAccess & 7u, disposition, options, &native);
		if (FAILED(brokerResult)) {
			// StorageFolder represents D:\ and \Device\CdRom0 themselves. Some
			// Windows versions expose child handles through
			// IStorageFolderHandleAccess but do not manufacture a HANDLE for the
			// folder root. Keep that root as a brokered kernel object; directory
			// enumeration and child opens still go through the retained folder.
			brokeredRoot = opticalRoot;
			SetLastError(HRESULT_FACILITY(brokerResult) == FACILITY_WIN32 ? HRESULT_CODE(brokerResult) : ERROR_ACCESS_DENIED);
		}
	}
	if (native == INVALID_HANDLE_VALUE && !brokeredRoot) {
		const auto status = StatusFromWin32(GetLastError()); WriteIoStatus(ioStatus, status, 0); return status;
	}
	auto object = std::make_shared<KernelObject>();
	object->kind = directory ? ObjectKind::Directory : ObjectKind::File;
	object->objectType = DataAddress(71);
	object->nativeHandle = native;
	object->path = path; object->signaled = false;
	object->brokeredOptical = optical;
	object->rawDevice = rawDevice;
	object->partitionNumber = partitionNumber;
	object->desiredAccess = desiredAccess;
	object->openOptions = options;
	object->deleteOnClose = (options & 0x00001000u) != 0;
	const auto handleStatus = CreateOutputHandle(object, handleOut);
	if (handleStatus != StatusSuccess) { WriteIoStatus(ioStatus, handleStatus, 0); return handleStatus; }
	WriteIoStatus(ioStatus, StatusSuccess, rawDevice || creation == OPEN_EXISTING ? FileOpened : FileCreated);
	return StatusSuccess;
}

std::chrono::steady_clock::time_point CxbxUwpKernelBridge::DecodeDeadline(
	std::uint32_t timeoutAddress, bool& infinite) const
{
	infinite = timeoutAddress == 0;
	if (infinite) return (std::chrono::steady_clock::time_point::max)();
	std::int64_t interval = 0;
	if (!Read(timeoutAddress, interval)) { infinite = false; return std::chrono::steady_clock::now(); }
	if (interval == 0) return std::chrono::steady_clock::now();
	const std::uint64_t ticks = interval < 0 ? 0ull - static_cast<std::uint64_t>(interval) : 0;
	auto addTicks = [](std::uint64_t value) {
		const std::uint64_t maximumTicks = static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) / 100u;
		if (value > maximumTicks) return (std::chrono::steady_clock::time_point::max)();
		return std::chrono::steady_clock::now() + std::chrono::nanoseconds(static_cast<std::int64_t>(value * 100u));
	};
	if (interval > 0) {
		FILETIME nowFile = {}; GetSystemTimeAsFileTime(&nowFile);
		const std::uint64_t now = (static_cast<std::uint64_t>(nowFile.dwHighDateTime) << 32) | nowFile.dwLowDateTime;
		if (static_cast<std::uint64_t>(interval) <= now) return std::chrono::steady_clock::now();
		return addTicks(static_cast<std::uint64_t>(interval) - now);
	}
	return addTicks(ticks);
}

void CxbxUwpKernelBridge::ExpireTimer(const ObjectPtr& object,
	std::chrono::steady_clock::time_point now)
{
	if (!object || object->kind != ObjectKind::Timer || !object->timerActive || now < object->due) return;
	object->signaled = true;
	SyncDispatcherSignal(object);
	FILETIME time = {}; GetSystemTimeAsFileTime(&time);
	if (object->timerDpc) QueueDpc(object->timerDpc, time.dwLowDateTime, time.dwHighDateTime);
	if (object->timerApcRoutine) {
		for (auto& owner : m_threads) {
			if (owner.id != object->timerThreadId || owner.state == ThreadState::Terminated) continue;
			owner.apcs.push_back({ 0, 0, 0, object->timerApcRoutine,
				object->timerApcContext, time.dwLowDateTime, time.dwHighDateTime,
				object->timerApcUserMode });
			Write(owner.guestThread + (object->timerApcUserMode ? 0x4A : 0x49), static_cast<std::uint8_t>(1));
			break;
		}
	}
	if (object->period.count() > 0) do object->due += object->period; while (object->due <= now);
	else object->timerActive = false;
	if (object->guestAddress)
		Write(object->guestAddress + 3, static_cast<std::uint8_t>(object->timerActive ? 1 : 0));
}

bool CxbxUwpKernelBridge::TrySatisfy(const ObjectPtr& object, ThreadContext* acquiringThread)
{
	if (!object) return false;
	ExpireTimer(object, std::chrono::steady_clock::now());
	if (object->kind == ObjectKind::Semaphore) {
		if (object->count <= 0) return false;
		--object->count;
		if (object->guestAddress) Write(object->guestAddress + 4, object->count);
		return true;
	}
	if (object->kind == ObjectKind::Mutant) {
		if (!acquiringThread && !m_threads.empty()) acquiringThread = &m_threads[m_currentThreadIndex];
		const std::uint32_t threadId = acquiringThread ? acquiringThread->id : 0;
		if (object->ownerThreadId == threadId && threadId) {
			++object->recursionCount;
			if (object->guestAddress) {
				std::int32_t signal = 0;
				Read(object->guestAddress + 4, signal);
				Write(object->guestAddress + 4, signal - 1);
			}
			return true;
		}
		if (!object->signaled) return false;
		object->signaled = false; object->ownerThreadId = threadId; object->recursionCount = 1;
		object->abandoned = false;
		if (object->guestAddress) {
			Write(object->guestAddress + 4, 0u);
			Write(object->guestAddress + 0x18, acquiringThread ? acquiringThread->guestThread : 0u);
			Write(object->guestAddress + 0x1C, static_cast<std::uint8_t>(0));
			LinkMutantToThread(object, acquiringThread);
		}
		return true;
	}
	if (object->kind == ObjectKind::Queue) {
		if (!object->signaled) return false;
		if (object->guestAddress) {
			std::uint32_t remaining = 0;
			Read(object->guestAddress + 4, remaining);
			object->signaled = remaining != 0;
		} else object->signaled = false;
		return true;
	}
	if (!object->signaled) return false;
	if (!object->manualReset) {
		object->signaled = false;
		SyncDispatcherSignal(object);
	}
	return true;
}

std::uint32_t CxbxUwpKernelBridge::PulseEventObject(const ObjectPtr& object)
{
	if (!object || object->kind != ObjectKind::Event) return 0;
	std::uint32_t previous = 0;
	{
		std::lock_guard<std::mutex> lock(m_objectMutex);
		previous = object->signaled ? 1u : 0u; object->signaled = true;
		if (object->guestAddress) Write(object->guestAddress + 4, 1u);
	}
	// The guest scheduler is cooperative; notify_all followed immediately by a
	// reset would otherwise lose every pulse. Satisfy exactly the waiters that
	// already existed at pulse time before clearing the event.
	WakeThreads();
	{
		std::lock_guard<std::mutex> lock(m_objectMutex);
		object->signaled = false; if (object->guestAddress) Write(object->guestAddress + 4, 0u);
	}
	m_objectChanged.notify_all();
	SyncReadyList();
	return previous;
}

std::uint32_t CxbxUwpKernelBridge::WaitObjects(const std::vector<ObjectPtr>& objects,
	bool waitAll, std::uint32_t timeoutAddress)
{
	if (objects.empty()) return StatusInvalidParameter;
	bool infinite = false;
	const auto deadline = DecodeDeadline(timeoutAddress, infinite);
	std::unique_lock<std::mutex> lock(m_objectMutex);
	ThreadContext* waitingThread = m_threads.empty() ? nullptr : &m_threads[m_currentThreadIndex];
	auto readyFor = [waitingThread](const ObjectPtr& object) {
		if (object->kind == ObjectKind::Semaphore) return object->count > 0;
		if (object->kind == ObjectKind::Mutant && waitingThread && object->ownerThreadId == waitingThread->id) return true;
		return object->signaled;
	};
	for (;;) {
		if (m_stopRequested.load(std::memory_order_acquire)) return StatusCancelled;
		if (waitAll) {
			bool ready = true;
			for (const auto& object : objects) {
				ExpireTimer(object, std::chrono::steady_clock::now());
				ready = ready && readyFor(object);
			}
			if (ready) { std::uint32_t abandonedStatus = StatusSuccess; for (std::size_t i = 0; i < objects.size(); ++i) { if (abandonedStatus == StatusSuccess && objects[i]->kind == ObjectKind::Mutant && objects[i]->abandoned) abandonedStatus = 0x80u + static_cast<std::uint32_t>(i); TrySatisfy(objects[i], waitingThread); } return abandonedStatus; }
		} else {
			for (std::size_t i = 0; i < objects.size(); ++i) { const bool abandoned = objects[i]->kind == ObjectKind::Mutant && objects[i]->abandoned; if (TrySatisfy(objects[i], waitingThread)) return static_cast<std::uint32_t>(i) + (abandoned ? 0x80u : 0u); }
		}
		if (!infinite && std::chrono::steady_clock::now() >= deadline) return StatusTimeout;
		const auto wake = infinite ? std::chrono::steady_clock::now() + std::chrono::milliseconds(10) :
			(std::min)(deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds(10));
		m_objectChanged.wait_until(lock, wake);
	}
}

void CxbxUwpKernelBridge::InitializeDispatcher(std::uint32_t address, std::uint8_t type,
	std::int32_t signalState)
{
	if (!IsRangeValid(address, 16)) return;
	FillGuestMemory(address, 0, 16);
	Write(address, type);
	std::uint8_t sizeInLongs = 4;
	switch (type) {
	case 2: sizeInLongs = 8; break;  // KMUTANT
	case 4: sizeInLongs = 10; break; // KQUEUE
	case 5: sizeInLongs = 5; break;  // KSEMAPHORE
	case 6: sizeInLongs = 68; break; // KTHREAD (0x110 bytes)
	case 8: case 9: sizeInLongs = 10; break; // KTIMER
	default: break;                  // KEVENT/KGATE
	}
	Write(address + 2, sizeInLongs);
	Write(address + 4, signalState);
	Write(address + 8, address + 8);
	Write(address + 12, address + 8);
}

void CxbxUwpKernelBridge::InitializeGuestThreadBody(std::uint32_t address)
{
	if (!IsRangeValid(address, 0x140)) return;
	// The scheduler consumes KTHREAD, but callers receive an ETHREAD. Clear the
	// complete public object so Create/ExitTime, ExitStatus and the IRP list never
	// expose stale pool contents.
	FillGuestMemory(address, 0, 0x140);
	InitializeDispatcher(address, 6, 0);
	Write(address + 0x10, address + 0x10);
	Write(address + 0x14, address + 0x10);

	// KAPC_STATE: one circular list per processor mode and the process which
	// owns the thread. Xbox code reads these fields directly around APC waits.
	Write(address + 0x34, address + 0x34);
	Write(address + 0x38, address + 0x34);
	Write(address + 0x3C, address + 0x3C);
	Write(address + 0x40, address + 0x3C);
	Write(address + 0x44, m_uniqueProcess);
	Write(address + 0x4B, static_cast<std::uint8_t>(1));

	Write(address + 0x7C, address + 0x7C);
	Write(address + 0x80, address + 0x7C);

	// Embedded timeout timer and its permanent wait block.
	const std::uint32_t timer = address + 0x88;
	InitializeDispatcher(timer, 8, 0);
	Write(timer + 0x18, 0u); Write(timer + 0x1C, 0u);
	Write(timer + 0x20, 0u); Write(timer + 0x24, 0u);
	const std::uint32_t waitBlock = address + 0xB0;
	Write(waitBlock, timer + 8); Write(waitBlock + 4, timer + 8);
	Write(waitBlock + 8, address); Write(waitBlock + 12, timer);
	Write(waitBlock + 16, 0u);
	Write(waitBlock + 20, static_cast<std::uint16_t>(StatusTimeout));
	Write(waitBlock + 22, static_cast<std::uint8_t>(0));

	// Suspend APC and semaphore. Routine execution is represented by the UWP
	// scheduler, but their public guest layout must match KeInitializeThread.
	const std::uint32_t suspendApc = address + 0xC8;
	Write(suspendApc, static_cast<std::uint16_t>(0x12));
	Write(suspendApc + 2, static_cast<std::uint8_t>(0));
	Write(suspendApc + 3, static_cast<std::uint8_t>(0));
	Write(suspendApc + 4, address);
	Write(suspendApc + 8, suspendApc + 8); Write(suspendApc + 12, suspendApc + 8);
	const std::uint32_t suspendSemaphore = address + 0xF0;
	InitializeDispatcher(suspendSemaphore, 5, 0);
	Write(suspendSemaphore + 0x10, 2u);
	Write(address + 0x104, address + 0x104);
	Write(address + 0x108, address + 0x104);
	FILETIME created = {}; GetSystemTimeAsFileTime(&created);
	Write(address + 0x110, (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime);
	Write(address + 0x120, 0x00000103u); // STATUS_PENDING until termination.
	Write(address + 0x124, address + 0x124); Write(address + 0x128, address + 0x124);
	Write(address + 0x134, address + 0x134); Write(address + 0x138, address + 0x134);
}

void CxbxUwpKernelBridge::LinkMutantToThread(const ObjectPtr& object, ThreadContext* thread)
{
	if (!object || object->kind != ObjectKind::Mutant || !thread ||
		!IsRangeValid(object->guestAddress, 0x20) || !IsRangeValid(thread->guestThread + 0x10, 8)) return;
	const std::uint32_t entry = object->guestAddress + 0x10;
	const std::uint32_t head = thread->guestThread + 0x10;
	std::uint32_t next = entry, previous = entry;
	Read(entry, next); Read(entry + 4, previous);
	if (next != entry || previous != entry) return;
	std::uint32_t tail = head; Read(head + 4, tail);
	if (!IsRangeValid(tail, 8)) tail = head;
	Write(entry, head); Write(entry + 4, tail);
	Write(tail, entry); Write(head + 4, entry);
}

void CxbxUwpKernelBridge::UnlinkMutant(const ObjectPtr& object)
{
	if (!object || object->kind != ObjectKind::Mutant || !IsRangeValid(object->guestAddress, 0x20)) return;
	const std::uint32_t entry = object->guestAddress + 0x10;
	std::uint32_t next = entry, previous = entry;
	if (Read(entry, next) && Read(entry + 4, previous) && next && previous && next != entry && previous != entry &&
		IsRangeValid(next, 8) && IsRangeValid(previous, 8)) {
		Write(previous, next); Write(next + 4, previous);
	}
	Write(entry, entry); Write(entry + 4, entry);
}

void CxbxUwpKernelBridge::SyncDispatcherSignal(const ObjectPtr& object)
{
	if (!object || !object->guestAddress) return;
	if ((object->kind == ObjectKind::File || object->kind == ObjectKind::Directory) &&
		object->objectType == DataAddress(71)) {
		Write(object->guestAddress + 0x3C, object->signaled ? 1u : 0u);
		return;
	}
	std::int32_t signal = object->signaled ? 1 : 0;
	if (object->kind == ObjectKind::Semaphore) signal = object->count;
	else if (object->kind == ObjectKind::Queue) return; // KQUEUE keeps its entry count in the guest list operations.
	else if (object->kind == ObjectKind::IoCompletion)
		signal = static_cast<std::int32_t>(object->completions.size());
	Write(object->guestAddress + 4, signal);
}

CxbxUwpKernelBridge::ThreadContext* CxbxUwpKernelBridge::FindThreadByGuestAddress(std::uint32_t address)
{
	for (auto& thread : m_threads) if (thread.guestThread == address) return &thread;
	return nullptr;
}

CxbxUwpKernelBridge::ThreadContext* CxbxUwpKernelBridge::FindThreadByHandle(std::uint32_t handle)
{
	auto object = GetHandle(handle);
	if (!object || object->kind != ObjectKind::Thread) return nullptr;
	for (auto& thread : m_threads) if (thread.id == object->threadId) return &thread;
	return nullptr;
}

std::uint32_t CxbxUwpKernelBridge::CreateGuestThread(std::uint32_t startRoutine,
	std::uint32_t startContext, std::uint32_t systemRoutine, std::uint32_t stackSize,
	bool suspended, std::uint32_t handleOut, std::uint32_t threadIdOut,
	std::uint32_t threadExtensionSize, std::uint32_t tlsDataSize)
{
	if (!startRoutine || !IsRangeValid(startRoutine, 1) || !IsRangeValid(handleOut, 4) ||
		(threadIdOut && !IsRangeValid(threadIdOut, 4))) return StatusInvalidParameter;
	stackSize = (std::max)(stackSize, 64u * 1024u);
	stackSize = (std::min)(stackSize, 1024u * 1024u);
	if (threadExtensionSize > 1024u * 1024u || tlsDataSize > stackSize) return StatusInvalidParameter;
	const std::uint32_t stack = Allocate(stackSize);
	const std::uint32_t guestThread = Allocate(0x140 + threadExtensionSize);
	if (!stack || !guestThread) { if (stack) Free(stack); if (guestThread) Free(guestThread); return StatusNoMemory; }

	ThreadContext thread = {};
	thread.id = m_nextThreadId++;
	thread.guestThread = guestThread;
	thread.basePriority = 8;
	thread.priority = 8;
	thread.suspendCount = suspended ? 1 : 0;
	thread.regs = *m_regs;
	thread.regs.eax = thread.regs.ebx = thread.regs.ecx = thread.regs.edx = 0;
	thread.regs.esi = thread.regs.edi = thread.regs.ebp = 0;
	thread.regs.esp = stack + stackSize - 16;
	thread.regs.ebp = thread.regs.esp;
	thread.regs.eip = systemRoutine ? systemRoutine : startRoutine;
	HRESULT tlsResult = InitializeThreadTls(thread.regs, stack + stackSize,
		thread.tib, thread.tlsVector, thread.tlsData, stackSize, tlsDataSize);
	if (FAILED(tlsResult)) { Free(stack); Free(guestThread); return StatusNoMemory; }
	thread.stackAllocation = stack;
	auto push = [this, &thread](std::uint32_t value) { thread.regs.esp -= 4; Write(thread.regs.esp, value); };
	if (systemRoutine) { push(startContext); push(startRoutine); }
	else push(startContext);
	push(StubBase + ThreadReturnOrdinal * StubStride);
	thread.state = suspended ? ThreadState::Suspended : ThreadState::Runnable;

	InitializeGuestThreadBody(guestThread);
	Write(guestThread + 0x10, guestThread + 0x10); Write(guestThread + 0x14, guestThread + 0x10);
	Write(guestThread + 0x1C, stack + stackSize);
	Write(guestThread + 0x20, stack);
	Write(guestThread + 0x24, thread.regs.esp);
	Write(guestThread + 0x28, thread.tlsVector);
	Write(guestThread + 0x2C, static_cast<std::uint8_t>(suspended ? 5 : 1));
	Write(guestThread + 0x32, thread.priority);
	Write(guestThread + 0x34, guestThread + 0x34); Write(guestThread + 0x38, guestThread + 0x34);
	Write(guestThread + 0x3C, guestThread + 0x3C); Write(guestThread + 0x40, guestThread + 0x3C);
	Write(guestThread + 0x44, m_uniqueProcess);
	Write(guestThread + 0x4B, static_cast<std::uint8_t>(1));
	Write(guestThread + 0x68, 0u);
	Write(guestThread + 0x6C, 60u);
	Write(guestThread + 0x70, thread.basePriority);
	Write(guestThread + 0x75, static_cast<std::uint8_t>(thread.suspendCount));
	Write(guestThread + 0x78, 0u); Write(guestThread + 0x7C, guestThread + 0x7C); Write(guestThread + 0x80, guestThread + 0x7C);
	const std::uint32_t processThreadHead = m_uniqueProcess + 8;
	const std::uint32_t threadEntry = guestThread + 0x104;
	std::uint32_t processTail = processThreadHead;
	Read(processThreadHead + 4, processTail);
	if (!IsRangeValid(processTail, 8)) processTail = processThreadHead;
	Write(threadEntry, processThreadHead); Write(threadEntry + 4, processTail);
	Write(processTail, threadEntry); Write(processThreadHead + 4, threadEntry);
	std::uint32_t processStackCount = 0; Read(m_uniqueProcess + 0x10, processStackCount);
	Write(m_uniqueProcess + 0x10, processStackCount + 1);
	Write(guestThread + 0x130, startRoutine);
	Write(guestThread + 0x134, guestThread + 0x134); Write(guestThread + 0x138, guestThread + 0x134);

	auto object = std::make_shared<KernelObject>();
	object->kind = ObjectKind::Thread; object->guestAddress = guestThread; object->bodyAllocation = guestThread;
	object->threadId = thread.id; object->objectType = DataAddress(259); object->manualReset = true;
	{ std::lock_guard<std::mutex> lock(m_objectMutex); m_guestObjects[guestThread] = object; m_dispatcherObjects[guestThread] = object; }
	const std::uint32_t uniqueHandle = CreateHandle(object);
	const std::uint32_t threadHandle = CreateHandle(object);
	thread.uniqueThread = uniqueHandle;
	Write(guestThread + 0x12C, uniqueHandle);
	Write(handleOut, threadHandle);
	if (threadIdOut) Write(threadIdOut, uniqueHandle);
	m_threads.push_back(thread);
	SyncReadyList();
	StartTlsCallbacks(m_threads.back(), 2);
	QueueThreadNotifications(guestThread, uniqueHandle, true);
	if (m_logger) {
		char line[180] = {}; sprintf_s(line, "[uwp-scheduler] thread %u criada: KTHREAD=0x%08X entry=0x%08X.\r\n", thread.id, guestThread, thread.regs.eip); m_logger(line);
	}
	return StatusSuccess;
}

bool CxbxUwpKernelBridge::LinkWaitBlocks(ThreadContext& thread, std::uint32_t waitBlockArray)
{
	UnlinkWaitBlocks(thread);
	if (thread.waitObjects.empty()) { Write(thread.guestThread + 0x58, 0u); return true; }
	thread.ownsWaitBlocks = waitBlockArray == 0;
	thread.waitBlocks.reserve(thread.waitObjects.size());
	for (std::size_t index = 0; index < thread.waitObjects.size(); ++index) {
		const std::uint32_t block = waitBlockArray ?
			waitBlockArray + static_cast<std::uint32_t>(index * 24) : Allocate(24);
		if (!block || !IsRangeValid(block, 24)) {
			UnlinkWaitBlocks(thread); Write(thread.guestThread + 0x58, 0u); return false;
		}
		FillGuestMemory(block, 0, 24);
		thread.waitBlocks.push_back(block);
	}
	for (std::size_t index = 0; index < thread.waitBlocks.size(); ++index) {
		const auto& object = thread.waitObjects[index];
		const std::uint32_t block = thread.waitBlocks[index];
		const std::uint32_t dispatcher = (object->kind == ObjectKind::File || object->kind == ObjectKind::Directory) &&
			object->objectType == DataAddress(71) ? object->guestAddress + 0x38 : object->guestAddress;
		if (!dispatcher || !IsRangeValid(dispatcher, 16)) {
			UnlinkWaitBlocks(thread);
			Write(thread.guestThread + 0x58, 0u);
			return false;
		}
		const std::uint32_t head = dispatcher + 8;
		std::uint32_t tail = head;
		if (!IsRangeValid(head, 8) || !Read(head + 4, tail) || !IsRangeValid(tail, 8)) tail = head;
		Write(block, head); Write(block + 4, tail); Write(tail, block); Write(head + 4, block);
		Write(block + 8, thread.guestThread); Write(block + 12, dispatcher);
		Write(block + 16, thread.waitBlocks[(index + 1) % thread.waitBlocks.size()]);
		Write(block + 20, static_cast<std::uint16_t>(index));
		Write(block + 22, static_cast<std::uint8_t>(thread.waitAll ? 0 : 1));
	}
	Write(thread.guestThread + 0x58, thread.waitBlocks.front());
	return true;
}

void CxbxUwpKernelBridge::UnlinkWaitBlocks(ThreadContext& thread)
{
	for (const std::uint32_t block : thread.waitBlocks) {
		std::uint32_t next = 0, previous = 0;
		if (Read(block, next) && Read(block + 4, previous) && next && previous &&
			IsRangeValid(next, 8) && IsRangeValid(previous, 8)) {
			Write(previous, next); Write(next + 4, previous);
		}
		if (thread.ownsWaitBlocks) Free(block);
	}
	thread.waitBlocks.clear();
	thread.ownsWaitBlocks = true;
	if (thread.guestThread) Write(thread.guestThread + 0x58, 0u);
}

void CxbxUwpKernelBridge::WakeThreads()
{
	const auto now = std::chrono::steady_clock::now();
	std::lock_guard<std::mutex> lock(m_objectMutex);
	std::unordered_set<KernelObject*> expiredTimers;
	for (const auto& pair : m_dispatcherObjects) {
		if (pair.second && expiredTimers.insert(pair.second.get()).second) ExpireTimer(pair.second, now);
	}
	// NtCreateTimer returns an executive handle and does not expose an embedded
	// KTIMER address. Such timers still participate in the dispatcher clock.
	for (const auto& pair : m_handles) {
		if (pair.second && pair.second->kind == ObjectKind::Timer &&
			expiredTimers.insert(pair.second.get()).second) ExpireTimer(pair.second, now);
	}
	for (auto& thread : m_threads) {
		auto completeWait = [this, &thread](std::uint32_t status) {
			// A wait owns an object-manager reference even if the originating handle
			// is closed by another thread. Preserve the guest body until its wait
			// blocks have been unlinked, then reap objects whose final handle vanished.
			const auto waitedObjects = thread.waitObjects;
			UnlinkWaitBlocks(thread);
			thread.queueWait = 0;
			if (status == StatusTimeout || status == StatusAlerted || status == StatusUserApc)
				thread.completionKeyOut = thread.completionApcOut = thread.completionIosbOut = 0;
			thread.state = thread.suspendCount ? ThreadState::Suspended : ThreadState::Runnable;
			thread.regs.eax = status;
			thread.alertable = false; thread.waitObjects.clear();
			std::unordered_set<KernelObject*> released;
			for (const auto& object : waitedObjects) {
				if (!object || !released.insert(object.get()).second) continue;
				if (thread.ownsWaitReferences && object->references) --object->references;
				if (object->allocationBase) Write(object->allocationBase, object->references);
				if (object->references || object->permanent) continue;
				bool hasHandle = false, stillWaiting = false;
				for (const auto& handle : m_handles) if (handle.second.get() == object.get()) { hasHandle = true; break; }
				if (!hasHandle) for (const auto& other : m_threads) {
					if (std::any_of(other.waitObjects.begin(), other.waitObjects.end(), [&object](const ObjectPtr& waited) { return waited.get() == object.get(); })) { stillWaiting = true; break; }
				}
				if (hasHandle || stillWaiting) continue;
				for (auto it = m_namedObjects.begin(); it != m_namedObjects.end();) {
					if (it->second.get() == object.get()) it = m_namedObjects.erase(it); else ++it;
				}
				for (auto it = m_dispatcherObjects.begin(); it != m_dispatcherObjects.end();) {
					if (it->second.get() == object.get()) it = m_dispatcherObjects.erase(it); else ++it;
				}
				m_guestObjects.erase(object->guestAddress);
				const std::uint32_t allocation = object->bodyAllocation ? object->bodyAllocation : object->allocationBase;
				if (allocation) { object->allocationBase = object->bodyAllocation = object->guestAddress = 0; Free(allocation); }
			}
			thread.ownsWaitReferences = false;
			Write(thread.guestThread + 0x2C, static_cast<std::uint8_t>(thread.suspendCount ? 5 : 1));
			Write(thread.guestThread + 0x2F, static_cast<std::uint8_t>(0));
			Write(thread.guestThread + 0x50, status);
		};
		const bool kernelApcPending = thread.suspendCount == 0 && thread.kernelApcDisable == 0 && std::any_of(thread.apcs.begin(), thread.apcs.end(), [](const ApcItem& apc) { return !apc.userMode; });
		const bool userApcPending = thread.suspendCount == 0 && thread.alertable && std::any_of(thread.apcs.begin(), thread.apcs.end(), [](const ApcItem& apc) { return apc.userMode; });
		if ((thread.state == ThreadState::Waiting || thread.state == ThreadState::Sleeping) && kernelApcPending) {
			thread.apcInterruptedState = thread.state; thread.resumeWaitAfterApc = true;
			thread.state = ThreadState::Runnable;
			Write(thread.guestThread + 0x2C, static_cast<std::uint8_t>(1)); continue;
		}
		if ((thread.state == ThreadState::Waiting || thread.state == ThreadState::Sleeping) && thread.alertable && thread.alerted[thread.waitMode]) {
			thread.alerted[thread.waitMode] = false;
			Write(thread.guestThread + 0x2D + thread.waitMode, static_cast<std::uint8_t>(0));
			completeWait(StatusAlerted); continue;
		}
		if ((thread.state == ThreadState::Waiting || thread.state == ThreadState::Sleeping) && userApcPending) {
			thread.userApcDeliveryPending = true;
			completeWait(StatusUserApc); continue;
		}
		if (thread.state == ThreadState::Sleeping && (!thread.infiniteWait && now >= thread.deadline)) {
			completeWait(StatusSuccess);
		}
		if (thread.state != ThreadState::Waiting) continue;
		bool ready = thread.waitAll;
		std::size_t readyIndex = 0;
		if (thread.waitAll) {
			for (const auto& object : thread.waitObjects) {
				ExpireTimer(object, now);
				bool objectReady = object->kind == ObjectKind::Semaphore ? object->count > 0 :
					(object->kind == ObjectKind::Mutant && object->ownerThreadId == thread.id) || object->signaled;
				if (object->kind == ObjectKind::Queue && thread.queueWait == object->guestAddress) {
					std::uint32_t current = 0, maximum = 0, signal = 0;
					Read(object->guestAddress + 0x18, current); Read(object->guestAddress + 0x1C, maximum); Read(object->guestAddress + 4, signal);
					objectReady = signal != 0 && current < maximum;
				}
				ready = ready && objectReady;
			}
		} else {
			ready = false;
			for (std::size_t i = 0; i < thread.waitObjects.size(); ++i) {
				auto& object = thread.waitObjects[i];
				ExpireTimer(object, now);
				bool objectReady = object->kind == ObjectKind::Semaphore ? object->count > 0 :
					(object->kind == ObjectKind::Mutant && object->ownerThreadId == thread.id) || object->signaled;
				if (object->kind == ObjectKind::Queue && thread.queueWait == object->guestAddress) {
					std::uint32_t current = 0, maximum = 0, signal = 0;
					Read(object->guestAddress + 0x18, current); Read(object->guestAddress + 0x1C, maximum); Read(object->guestAddress + 4, signal);
					objectReady = signal != 0 && current < maximum;
				}
				if (objectReady) { ready = true; readyIndex = i; break; }
			}
		}
		if (ready) {
			bool abandonedWait = false;
			std::uint32_t abandonedWaitAllStatus = StatusSuccess;
			std::uint32_t queueResult = 0;
			std::uint32_t irpResult = StatusSuccess;
			const bool completedIrpWait = thread.pendingIrp != 0;
			ObjectPtr readyObject = thread.waitObjects.empty() ? nullptr : thread.waitObjects[thread.waitAll ? 0 : readyIndex];
			if (completedIrpWait && IsRangeValid(thread.pendingIrp + 0x18, 1)) {
				std::uint32_t information = 0; Read(thread.pendingIrp + 0x10, irpResult); Read(thread.pendingIrp + 0x14, information);
				if (thread.pendingIrpInformationOut) Write(thread.pendingIrpInformationOut, information);
			}
			if (thread.completionIosbOut && readyObject && readyObject->kind == ObjectKind::IoCompletion && !readyObject->completions.empty()) {
				const auto packet = readyObject->completions.front(); readyObject->completions.pop_front();
				if (thread.completionKeyOut) Write(thread.completionKeyOut, packet[0]);
				if (thread.completionApcOut) Write(thread.completionApcOut, packet[1]);
				WriteIoStatus(thread.completionIosbOut, packet[2], packet[3]);
				readyObject->signaled = !readyObject->completions.empty();
				SyncDispatcherSignal(readyObject);
				thread.completionKeyOut = thread.completionApcOut = thread.completionIosbOut = 0;
			}
			if (thread.queueWait) {
				std::uint32_t first = 0, next = 0, signal = 0;
				Read(thread.queueWait + 0x10, first);
				if (first != thread.queueWait + 0x10 && Read(first, next)) {
					Write(thread.queueWait + 0x10, next); Write(next + 4, thread.queueWait + 0x10);
					Read(thread.queueWait + 4, signal); if (signal) Write(thread.queueWait + 4, signal - 1);
					std::uint32_t currentCount = 0; Read(thread.queueWait + 0x18, currentCount); Write(thread.queueWait + 0x18, currentCount + 1);
					queueResult = first;
				}
				thread.queueWait = 0;
			}
			if (thread.waitAll) for (std::size_t i = 0; i < thread.waitObjects.size(); ++i) { const auto& object = thread.waitObjects[i]; if (abandonedWaitAllStatus == StatusSuccess && object->kind == ObjectKind::Mutant && object->abandoned) abandonedWaitAllStatus = 0x80u + static_cast<std::uint32_t>(i); TrySatisfy(object, &thread); }
			else { abandonedWait = thread.waitObjects[readyIndex]->kind == ObjectKind::Mutant && thread.waitObjects[readyIndex]->abandoned; TrySatisfy(thread.waitObjects[readyIndex], &thread); }
			if (thread.criticalSectionWait) {
				// RtlEnterCriticalSection already incremented LockCount before it
				// yielded. Complete the ownership transfer at the exact point the
				// synchronization event selects this waiter.
				Write(thread.criticalSectionWait + 0x14, 1u);
				Write(thread.criticalSectionWait + 0x18, thread.guestThread);
				thread.criticalSectionWait = 0;
			}
			const std::uint32_t waitStatus = completedIrpWait ? irpResult : queueResult ? queueResult :
				(thread.waitAll ? abandonedWaitAllStatus :
				static_cast<std::uint32_t>(readyIndex) + (abandonedWait ? 0x80u : 0u));
			completeWait(waitStatus);
			if (completedIrpWait) {
				const std::uint32_t irp = thread.pendingIrp; thread.pendingIrp = thread.pendingIrpInformationOut = 0;
				if (thread.freePendingIrp) Free(irp); thread.freePendingIrp = false;
				if (readyObject && readyObject->guestAddress) { m_dispatcherObjects.erase(readyObject->guestAddress); Free(readyObject->guestAddress); }
			}
		} else if (!thread.infiniteWait && now >= thread.deadline) {
			completeWait(StatusTimeout);
		}
	}
}

void CxbxUwpKernelBridge::SyncReadyList()
{
	if (!m_uniqueProcess || !IsRangeValid(m_uniqueProcess, 8)) return;
	const std::uint32_t head = m_uniqueProcess;
	Write(head, head); Write(head + 4, head);
	std::uint32_t tail = head;
	for (auto& thread : m_threads) {
		const std::uint32_t entry = thread.guestThread + 0x5C;
		if (!IsRangeValid(entry, 8)) continue;
		Write(entry, entry); Write(entry + 4, entry);
		if (thread.state != ThreadState::Runnable) continue;
		Write(entry, head); Write(entry + 4, tail);
		Write(tail, entry); Write(head + 4, entry);
		tail = entry;
	}
}

bool CxbxUwpKernelBridge::DeliverPendingApc(ThreadContext& thread)
{
	// APC delivery is suppressed at APC_LEVEL and above. Pending bits stay set
	// until KfLowerIrql/KiUnlockDispatcherDatabase returns the processor to PASSIVE_LEVEL.
	if (m_currentIrql >= 1 || thread.apcs.empty() || thread.deliveringApc) return false;
	auto selected = std::find_if(thread.apcs.begin(), thread.apcs.end(), [&thread](const ApcItem& apc) {
		return apc.userMode ? (thread.alertable || thread.userApcDeliveryPending) : thread.kernelApcDisable == 0;
	});
	if (selected == thread.apcs.end()) return false;
	const bool currentRunning = m_currentThreadIndex < m_threads.size() &&
		&m_threads[m_currentThreadIndex] == &thread && thread.state == ThreadState::Running;
	if (currentRunning) thread.regs = *m_regs;
	const ApcItem apc = *selected;
	thread.apcs.erase(selected);
	if (apc.address) {
		std::uint32_t next = 0, previous = 0;
		if (Read(apc.address + 8, next) && Read(apc.address + 12, previous) && next && previous &&
			IsRangeValid(next, 8) && IsRangeValid(previous, 8)) {
			Write(previous, next); Write(next + 4, previous);
		}
		Write(apc.address + 8, apc.address + 8); Write(apc.address + 12, apc.address + 8);
		Write(apc.address + 3, static_cast<std::uint8_t>(0));
	}
	const bool sameModePending = std::any_of(thread.apcs.begin(), thread.apcs.end(),
		[apc](const ApcItem& item) { return item.userMode == apc.userMode; });
	Write(thread.guestThread + (apc.userMode ? 0x4A : 0x49), static_cast<std::uint8_t>(sameModePending));
	thread.apcResume = thread.regs;
	thread.activeApc = apc;
	thread.deliveringApc = true;
	thread.apcSavedIrql = m_currentIrql;
	auto push = [this, &thread](std::uint32_t value) { thread.regs.esp -= 4; Write(thread.regs.esp, value); };
	if (apc.kernelRoutine) {
		Write(thread.guestThread + 0x48, static_cast<std::uint8_t>(1));
		thread.regs.esp = (thread.regs.esp - 16) & ~3u;
		thread.apcScratch = thread.regs.esp;
		Write(thread.apcScratch, apc.normalRoutine); Write(thread.apcScratch + 4, apc.context);
		Write(thread.apcScratch + 8, apc.argument1); Write(thread.apcScratch + 12, apc.argument2);
		push(thread.apcScratch + 12); push(thread.apcScratch + 8); push(thread.apcScratch + 4);
		push(thread.apcScratch); push(apc.address);
		push(StubBase + ApcReturnOrdinal * StubStride);
		thread.regs.eip = apc.kernelRoutine; thread.apcStage = 1;
		SetCurrentIrql(1);
	} else {
		push(apc.argument2); push(apc.argument1); push(apc.context);
		push(StubBase + ApcReturnOrdinal * StubStride);
		thread.regs.eip = apc.normalRoutine; thread.apcStage = 2;
	}
	if (currentRunning) *m_regs = thread.regs;
	return true;
}

bool CxbxUwpKernelBridge::QueueDpc(std::uint32_t address, std::uint32_t argument1,
	std::uint32_t argument2)
{
	if (!IsRangeValid(address, 28)) return false;
	std::uint8_t inserted = 0; std::uint32_t routine = 0, context = 0;
	Read(address + 2, inserted); Read(address + 12, routine); Read(address + 16, context);
	if (inserted || !routine || !IsRangeValid(routine, 1)) return false;
	Write(address + 2, static_cast<std::uint8_t>(1)); Write(address + 20, argument1); Write(address + 24, argument2);
	if (m_currentThreadIndex < m_threads.size()) {
		const std::uint32_t head = m_threads[m_currentThreadIndex].tib + 0x50;
		std::uint32_t tail = head; Read(head + 4, tail);
		if (!IsRangeValid(tail, 8)) tail = head;
		Write(address + 4, head); Write(address + 8, tail);
		Write(tail, address + 4); Write(head + 4, address + 4);
	}
	m_dpcQueue.push_back({ address, routine, context, argument1, argument2 });
	m_softwareInterrupts |= 1u << 2;
	return true;
}

bool CxbxUwpKernelBridge::DeliverPendingDpc()
{
	if (m_dpcActive || m_interruptActive || m_synchronizeActive || m_currentIrql >= 2 || m_dpcQueue.empty()) return false;
	const DpcItem dpc = m_dpcQueue.front();
	m_dpcQueue.erase(m_dpcQueue.begin());
	std::uint32_t next = 0, previous = 0;
	if (Read(dpc.address + 4, next) && Read(dpc.address + 8, previous) && next && previous &&
		IsRangeValid(next, 8) && IsRangeValid(previous, 8)) {
		Write(previous, next); Write(next + 4, previous);
	}
	Write(dpc.address + 4, dpc.address + 4); Write(dpc.address + 8, dpc.address + 4);
	if (!dpc.routine || !IsRangeValid(dpc.routine, 1)) {
		Write(dpc.address + 2, static_cast<std::uint8_t>(0));
		return false;
	}
	m_softwareInterrupts &= ~(1u << 2);
	if (!m_dpcQueue.empty()) m_softwareInterrupts |= 1u << 2;
	Write(dpc.address + 2, static_cast<std::uint8_t>(0));
	m_dpcResume = *m_regs;
	m_savedDpcIrql = m_currentIrql;
	m_dpcActive = true;
	SetCurrentIrql(2);
	auto push = [this](std::uint32_t value) { m_regs->esp -= 4; Write(m_regs->esp, value); };
	push(dpc.argument2); push(dpc.argument1); push(dpc.context); push(dpc.address);
	push(StubBase + DpcReturnOrdinal * StubStride);
	m_regs->eip = dpc.routine;
	return true;
}

bool CxbxUwpKernelBridge::DeliverPendingInterrupt()
{
	InterruptItem interrupt = {};
	{
		std::lock_guard<std::mutex> lock(m_interruptMutex);
		auto selected = m_pendingInterrupts.end();
		std::uint32_t selectedIrql = 0;
		for (auto it = m_pendingInterrupts.begin(); it != m_pendingInterrupts.end(); ++it) {
			auto found = m_interrupts.find(*it);
			if (found != m_interrupts.end() && found->second.connected && !found->second.inService &&
				(found->second.pulsePending || found->second.assertedSources) && found->second.irql > m_currentIrql &&
				(found->second.irql >= selectedIrql)) { selected = it; selectedIrql = found->second.irql; interrupt = found->second; }
		}
		if (selected == m_pendingInterrupts.end()) return false;
		auto active = m_interrupts.find(*selected);
		if (active == m_interrupts.end()) return false;
		active->second.inService = true;
		active->second.pulsePending = false;
		m_pendingInterrupts.erase(selected);
	}
	if (!interrupt.routine || !IsRangeValid(interrupt.routine, 1)) {
		std::lock_guard<std::mutex> lock(m_interruptMutex);
		auto active = m_interrupts.find(interrupt.busLevel);
		if (active != m_interrupts.end() && active->second.address == interrupt.address)
			active->second.inService = false;
		return false;
	}
	m_interruptFrames.push_back({ *m_regs, m_activeInterrupt, m_activeInterruptLevel, m_currentIrql, m_interruptActive });
	m_interruptResume = *m_regs;
	m_savedInterruptIrql = m_currentIrql;
	m_interruptActive = true;
	SetCurrentIrql(static_cast<std::uint8_t>((std::min)(interrupt.irql, 31u)));
	m_activeInterrupt = interrupt.address;
	m_activeInterruptLevel = interrupt.busLevel;
	auto push = [this](std::uint32_t value) { m_regs->esp -= 4; Write(m_regs->esp, value); };
	push(interrupt.context); push(interrupt.address);
	push(StubBase + InterruptReturnOrdinal * StubStride);
	m_regs->eip = interrupt.routine;
	return true;
}

bool CxbxUwpKernelBridge::SwitchThread(bool makeCurrentRunnable)
{
	if (m_threads.empty() || m_currentThreadIndex >= m_threads.size()) return false;
	auto& current = m_threads[m_currentThreadIndex];
	if (current.state == ThreadState::Running) {
		if (current.tib) Read(current.tib, current.exceptionList);
		current.regs = *m_regs;
		if (makeCurrentRunnable) current.state = ThreadState::Runnable;
		Write(current.guestThread + 0x2C, static_cast<std::uint8_t>(current.state == ThreadState::Runnable ? 1 : 5));
	}
	for (;;) {
		WakeThreads();
		std::int8_t highestPriority = (std::numeric_limits<std::int8_t>::min)();
		for (const auto& candidate : m_threads) {
			if (candidate.state == ThreadState::Runnable) highestPriority = (std::max)(highestPriority, candidate.priority);
		}
		for (std::size_t offset = 1; offset <= m_threads.size(); ++offset) {
			const std::size_t index = (m_currentThreadIndex + offset) % m_threads.size();
			if (m_threads[index].state != ThreadState::Runnable || m_threads[index].priority != highestPriority) continue;
			m_currentThreadIndex = index;
			auto& next = m_threads[index];
			next.state = ThreadState::Running;
			next.quantumRemaining = 60;
			Write(next.guestThread + 0x6C, next.quantumRemaining);
			std::uint32_t switches = 0; Read(next.guestThread + 0x4C, switches); Write(next.guestThread + 0x4C, switches + 1);
			Write(next.guestThread + 0x2C, static_cast<std::uint8_t>(2));
			SyncReadyList();
			SyncProcessorControlRegion(next);
			*m_regs = next.regs;
			DeliverPendingApc(next);
			*m_regs = next.regs;
			m_currentThread = next.guestThread;
			return true;
		}
		if (m_stopRequested.load(std::memory_order_acquire)) return false;
		bool pending = false;
		for (const auto& thread : m_threads) if (thread.state != ThreadState::Terminated && thread.state != ThreadState::Suspended) pending = true;
		if (!pending) return false;
		if (DeliverPendingInterrupt() || DeliverPendingDpc()) return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

void CxbxUwpKernelBridge::ScheduleDelay(std::uint32_t timeoutAddress, bool alertable,
	std::uint8_t waitMode, std::uint8_t waitReason)
{
	auto& thread = m_threads[m_currentThreadIndex];
	thread.regs = *m_regs;
	std::int64_t rawTimeout = -1;
	const bool polling = timeoutAddress && Read(timeoutAddress, rawTimeout) && rawTimeout == 0;
	if (m_currentIrql > (polling ? 2 : 1)) { thread.regs.eax = StatusInvalidParameter; *m_regs = thread.regs; return; }
	UnlinkWaitBlocks(thread); thread.waitObjects.clear();
	Write(thread.guestThread + 0x56, static_cast<std::uint8_t>(0));
	thread.alertable = alertable;
	thread.waitMode = waitMode;
	if (alertable && thread.alerted[waitMode]) { thread.alerted[waitMode] = false; Write(thread.guestThread + 0x2D + waitMode, static_cast<std::uint8_t>(0)); thread.alertable = false; thread.regs.eax = StatusAlerted; *m_regs = thread.regs; return; }
	thread.deadline = DecodeDeadline(timeoutAddress, thread.infiniteWait);
	if (!thread.infiniteWait && thread.deadline <= std::chrono::steady_clock::now()) {
		thread.alertable = false; thread.regs.eax = StatusSuccess; *m_regs = thread.regs; return;
	}
	thread.state = ThreadState::Sleeping;
	Write(thread.guestThread + 0x2C, static_cast<std::uint8_t>(5));
	Write(thread.guestThread + 0x2F, static_cast<std::uint8_t>(alertable));
	Write(thread.guestThread + 0x50, 0x00000103u);
	Write(thread.guestThread + 0x54, m_currentIrql);
	Write(thread.guestThread + 0x55, waitMode);
	Write(thread.guestThread + 0x57, waitReason);
	Write(thread.guestThread + 0x64, m_lastExportedTick);
	SyncReadyList();
	SwitchThread(false);
}

void CxbxUwpKernelBridge::ScheduleWait(std::vector<ObjectPtr> objects, bool waitAll,
	bool alertable, std::uint32_t timeoutAddress, std::uint8_t waitMode,
	std::uint8_t waitReason, std::uint32_t waitBlockArray)
{
	auto& thread = m_threads[m_currentThreadIndex];
	thread.regs = *m_regs;
	std::int64_t rawTimeout = -1;
	const bool polling = timeoutAddress && Read(timeoutAddress, rawTimeout) && rawTimeout == 0;
	if (m_currentIrql > (polling ? 2 : 1)) { thread.regs.eax = StatusInvalidParameter; *m_regs = thread.regs; return; }
	// KiWaitTest checks the dispatcher state before linking wait blocks.  This
	// fast path is essential for synchronization events, semaphores and mutants:
	// sleeping first can lose a signal and, with a single runnable guest thread,
	// leave the title parked forever.
	const auto now = std::chrono::steady_clock::now();
	for (const auto& object : objects) ExpireTimer(object, now);
	std::size_t readyIndex = 0;
	auto isReady = [this, &thread](const ObjectPtr& object) {
		if (!object) return false;
		if (object->kind == ObjectKind::Semaphore) return object->count > 0;
		if (object->kind == ObjectKind::Mutant && object->ownerThreadId == thread.id) return true;
		if (object->kind == ObjectKind::Queue && thread.queueWait == object->guestAddress) {
			std::uint32_t current = 0, maximum = 0, signal = 0;
			Read(object->guestAddress + 0x18, current); Read(object->guestAddress + 0x1C, maximum); Read(object->guestAddress + 4, signal);
			return signal != 0 && current < maximum;
		}
		return object->signaled;
	};
	bool ready = !objects.empty();
	if (waitAll) {
		for (const auto& object : objects) if (!isReady(object)) { ready = false; break; }
	} else {
		ready = false;
		for (std::size_t i = 0; i < objects.size(); ++i) if (isReady(objects[i])) {
			ready = true; readyIndex = i; break;
		}
	}
	if (ready) {
		bool abandoned = false;
		std::uint32_t abandonedWaitAllStatus = StatusSuccess;
		std::uint32_t queueResult = 0;
		const auto& selectedObject = objects[waitAll ? 0 : readyIndex];
		if (!waitAll && selectedObject->kind == ObjectKind::Queue && thread.queueWait == selectedObject->guestAddress) {
			std::uint32_t first = 0, next = 0, signal = 0, current = 0;
			Read(selectedObject->guestAddress + 0x10, first);
			if (first != selectedObject->guestAddress + 0x10 && Read(first, next)) {
				Write(selectedObject->guestAddress + 0x10, next); Write(next + 4, selectedObject->guestAddress + 0x10);
				Read(selectedObject->guestAddress + 4, signal); if (signal) Write(selectedObject->guestAddress + 4, signal - 1);
				Read(selectedObject->guestAddress + 0x18, current); Write(selectedObject->guestAddress + 0x18, current + 1);
				queueResult = first;
			}
			thread.queueWait = 0;
		}
		if (waitAll) {
			for (std::size_t i = 0; i < objects.size(); ++i) {
				const auto& object = objects[i];
				if (abandonedWaitAllStatus == StatusSuccess && object->kind == ObjectKind::Mutant && object->abandoned)
					abandonedWaitAllStatus = 0x80u + static_cast<std::uint32_t>(i);
				TrySatisfy(object, &thread);
			}
		} else {
			abandoned = objects[readyIndex]->kind == ObjectKind::Mutant && objects[readyIndex]->abandoned;
			TrySatisfy(objects[readyIndex], &thread);
		}
		if (thread.criticalSectionWait) {
			Write(thread.criticalSectionWait + 0x14, 1u);
			Write(thread.criticalSectionWait + 0x18, thread.guestThread);
			thread.criticalSectionWait = 0;
		}
		thread.regs.eax = queueResult ? queueResult : waitAll ? abandonedWaitAllStatus :
			static_cast<std::uint32_t>(readyIndex) + (abandoned ? 0x80u : 0u);
		*m_regs = thread.regs;
		return;
	}
	bool infinite = true;
	const auto deadline = DecodeDeadline(timeoutAddress, infinite);
	if (!infinite && deadline <= now) {
		thread.regs.eax = StatusTimeout;
		*m_regs = thread.regs;
		return;
	}
	thread.waitObjects = std::move(objects);
	Write(thread.guestThread + 0x56, static_cast<std::uint8_t>(0));
	thread.waitAll = waitAll;
	thread.alertable = alertable;
	thread.waitMode = waitMode;
	if (alertable && thread.alerted[waitMode]) { thread.alerted[waitMode] = false; Write(thread.guestThread + 0x2D + waitMode, static_cast<std::uint8_t>(0)); thread.alertable = false; thread.waitObjects.clear(); thread.regs.eax = StatusAlerted; *m_regs = thread.regs; return; }
	if (!LinkWaitBlocks(thread, waitBlockArray)) {
		thread.waitObjects.clear(); thread.alertable = false;
		thread.regs.eax = StatusInvalidParameter; *m_regs = thread.regs; return;
	}
	{
		std::unordered_set<KernelObject*> retained;
		for (const auto& object : thread.waitObjects) if (object && retained.insert(object.get()).second) {
			++object->references;
			if (object->allocationBase) Write(object->allocationBase, object->references);
		}
		thread.ownsWaitReferences = true;
	}
	thread.deadline = deadline;
	thread.infiniteWait = infinite;
	thread.state = ThreadState::Waiting;
	Write(thread.guestThread + 0x2C, static_cast<std::uint8_t>(5));
	Write(thread.guestThread + 0x2F, static_cast<std::uint8_t>(alertable));
	Write(thread.guestThread + 0x50, 0x00000103u);
	Write(thread.guestThread + 0x54, m_currentIrql);
	Write(thread.guestThread + 0x55, waitMode);
	Write(thread.guestThread + 0x57, waitReason);
	Write(thread.guestThread + 0x64, m_lastExportedTick);
	SyncReadyList();
	SwitchThread(false);
}

void CxbxUwpKernelBridge::TerminateCurrentThread(std::uint32_t status)
{
	if (m_threads.empty()) { cpu_exit(m_cpu); return; }
	auto& thread = m_threads[m_currentThreadIndex];
	UnlinkWaitBlocks(thread);
	{
		const auto waitedObjects = std::move(thread.waitObjects);
		thread.waitObjects.clear();
		std::unordered_set<KernelObject*> released;
		for (const auto& object : waitedObjects)
			if (object && released.insert(object.get()).second) DereferenceObject(object, thread.ownsWaitReferences);
		thread.ownsWaitReferences = false;
	}
	if (thread.associatedQueue) {
		std::uint32_t current = 0; Read(thread.associatedQueue + 0x18, current);
		if (current) Write(thread.associatedQueue + 0x18, current - 1);
		const std::uint32_t entry = thread.guestThread + 0x7C;
		std::uint32_t next = 0, previous = 0;
		if (Read(entry, next) && Read(entry + 4, previous) && next && previous &&
			IsRangeValid(next, 8) && IsRangeValid(previous, 8)) { Write(previous, next); Write(next + 4, previous); }
		Write(thread.guestThread + 0x78, 0u); Write(entry, entry); Write(entry + 4, entry);
		thread.queueWait = thread.associatedQueue = 0;
	}
	if (!thread.tlsDetached && !m_tlsCallbacks.empty()) {
		thread.exitStatus = status; thread.terminateAfterTls = true; thread.tlsDetached = true; thread.regs = *m_regs;
		if (StartTlsCallbacks(thread, thread.id == 1 ? 0u : 3u)) { *m_regs = thread.regs; return; }
	}
	while (!thread.apcs.empty()) {
		const ApcItem apc = thread.apcs.front(); thread.apcs.erase(thread.apcs.begin());
		if (apc.address) {
			std::uint32_t next = 0, previous = 0; Read(apc.address + 8, next); Read(apc.address + 12, previous);
			if (next && previous && IsRangeValid(next, 8) && IsRangeValid(previous, 8)) { Write(previous, next); Write(next + 4, previous); }
			Write(apc.address + 8, apc.address + 8); Write(apc.address + 12, apc.address + 8);
			Write(apc.address + 3, static_cast<std::uint8_t>(0));
		}
		Write(thread.guestThread + (apc.userMode ? 0x4A : 0x49), static_cast<std::uint8_t>(0));
		if (!apc.rundownRoutine || !IsRangeValid(apc.rundownRoutine, 1)) continue;
		thread.exitStatus = status; thread.deliveringApc = true; thread.terminatingApcRundown = true;
		thread.apcStage = 3; thread.activeApc = apc; thread.regs = *m_regs;
		thread.regs.esp -= 4; Write(thread.regs.esp, apc.address);
		thread.regs.esp -= 4; Write(thread.regs.esp, StubBase + ApcReturnOrdinal * StubStride);
		thread.regs.eip = apc.rundownRoutine; *m_regs = thread.regs; return;
	}
	thread.exitStatus = status;
	thread.state = ThreadState::Terminated;
	{
		const std::uint32_t entry = thread.guestThread + 0x104;
		std::uint32_t next = entry, previous = entry;
		if (Read(entry, next) && Read(entry + 4, previous) && next && previous && next != entry && previous != entry &&
			IsRangeValid(next, 8) && IsRangeValid(previous, 8)) {
			Write(previous, next); Write(next + 4, previous);
			Write(entry, entry); Write(entry + 4, entry);
			std::uint32_t stackCount = 0; Read(m_uniqueProcess + 0x10, stackCount);
			if (stackCount) Write(m_uniqueProcess + 0x10, stackCount - 1);
		}
	}
	Write(thread.guestThread + 4, 1u);
	Write(thread.guestThread + 0x2C, static_cast<std::uint8_t>(4));
	Write(thread.guestThread + 0x77, static_cast<std::uint8_t>(1));
	FILETIME exited = {}; GetSystemTimeAsFileTime(&exited);
	Write(thread.guestThread + 0x118, (static_cast<std::uint64_t>(exited.dwHighDateTime) << 32) | exited.dwLowDateTime);
	Write(thread.guestThread + 0x120, status);
	QueueThreadNotifications(thread.guestThread, thread.uniqueThread ? thread.uniqueThread : thread.id, false);
	{
		std::lock_guard<std::mutex> lock(m_objectMutex);
		for (auto& pair : m_handles) if (pair.second->kind == ObjectKind::Thread && pair.second->threadId == thread.id) { pair.second->signaled = true; SyncDispatcherSignal(pair.second); }
		std::unordered_set<KernelObject*> abandonedMutants;
		auto abandonOwnedMutant = [this, &thread, &abandonedMutants](const ObjectPtr& object) {
			if (!object || object->kind != ObjectKind::Mutant ||
				object->ownerThreadId != thread.id || !abandonedMutants.insert(object.get()).second) return;
			object->ownerThreadId = 0;
			object->recursionCount = 0;
			object->abandoned = true;
			object->signaled = true;
			if (object->guestAddress) {
				UnlinkMutant(object);
				Write(object->guestAddress + 4, 1u);
				Write(object->guestAddress + 0x18, 0u);
				Write(object->guestAddress + 0x1C, static_cast<std::uint8_t>(1));
			}
		};
		// Executive mutants created by NtCreateMutant only have handles, whereas
		// KMUTANTs initialized by KeInitializeMutant live in the dispatcher map.
		// Both classes are abandoned by the Xbox kernel when their owner exits.
		for (auto& pair : m_handles) abandonOwnedMutant(pair.second);
		for (auto& pair : m_dispatcherObjects) {
			abandonOwnedMutant(pair.second);
		}
	}
	const std::uint32_t uniqueThreadHandle = thread.uniqueThread; thread.uniqueThread = 0;
	if (uniqueThreadHandle) CloseGuestHandle(uniqueThreadHandle);
	m_objectChanged.notify_all();
	WakeThreads();
	SyncReadyList();
	const std::uint32_t stackAllocation = thread.stackAllocation;
	const std::uint32_t tlsVector = thread.tlsVector, tlsData = thread.tlsData;
	if (!SwitchThread(false)) cpu_exit(m_cpu);
	else DeliverThreadNotification();
	if (tlsData) Free(tlsData); if (tlsVector) Free(tlsVector); if (stackAllocation) Free(stackAllocation);
}

void CxbxUwpKernelBridge::QueueThreadNotifications(std::uint32_t thread,
	std::uint32_t threadId, bool create)
{
	for (const std::uint32_t routine : m_threadNotifyRoutines) {
		if (routine && IsRangeValid(routine, 1)) m_threadNotifications.push_back({ routine, thread, threadId, create });
	}
}

bool CxbxUwpKernelBridge::DeliverThreadNotification()
{
	if (m_threadNotifyActive || m_threadNotifications.empty()) return false;
	const ThreadNotifyItem item = m_threadNotifications.front();
	m_threadNotifications.pop_front();
	m_threadNotifyResume = *m_regs;
	m_threadNotifyActive = true;
	auto push = [this](std::uint32_t value) { m_regs->esp -= 4; Write(m_regs->esp, value); };
	push(item.create ? 1u : 0u); push(item.threadId); push(item.thread);
	push(StubBase + ThreadNotifyReturnOrdinal * StubStride);
	m_regs->eip = item.routine;
	return true;
}

bool CxbxUwpKernelBridge::StartShutdownNotifications(bool terminateAfter)
{
	if (m_shutdownNotificationActive) return false;
	m_shutdownResume = *m_regs;
	m_shutdownRegistrationIndex = 0;
	m_shutdownNotificationActive = true;
	m_terminateAfterShutdownNotifications = terminateAfter;
	return ContinueShutdownNotifications();
}

bool CxbxUwpKernelBridge::ContinueShutdownNotifications()
{
	while (m_shutdownRegistrationIndex < m_shutdownRegistrations.size()) {
		const std::uint32_t registration = m_shutdownRegistrations[m_shutdownRegistrationIndex++];
		std::uint32_t routine = 0;
		if (!IsRangeValid(registration, 16) || !Read(registration, routine) || !routine || !IsRangeValid(routine, 1)) continue;
		*m_regs = m_shutdownResume;
		m_regs->esp -= 4; Write(m_regs->esp, registration);
		m_regs->esp -= 4; Write(m_regs->esp, StubBase + ShutdownReturnOrdinal * StubStride);
		m_regs->eip = routine;
		return true;
	}
	*m_regs = m_shutdownResume;
	m_shutdownNotificationActive = false;
	return false;
}

void CxbxUwpKernelBridge::RaiseGuestException(std::uint32_t code,
	std::uint32_t argumentCount, const char* source, std::uint32_t sourceRecord,
	std::uint32_t exceptionFlags, std::uint32_t exceptionAddress)
{
	FinishStdcall(argumentCount);
	if (m_exceptionPending) { m_exceptionFrames.push_back({ m_exceptionResume, m_exceptionCode,
		m_exceptionRegistration, m_exceptionRecord, m_exceptionContext, m_exceptionDispatcherContext }); m_exceptionPending = false;
		m_exceptionRecord = m_exceptionContext = m_exceptionDispatcherContext = 0; m_exceptionRegistration = 0xFFFFFFFFu; }
	std::uint32_t registration = 0xFFFFFFFFu;
	const std::uint32_t tib = m_regs->fs_hidden.base;
	if (tib && Read(tib, registration) && registration != 0xFFFFFFFFu) {
		const std::uint32_t record = Allocate(80);
		const std::uint32_t context = Allocate(0x238);
		const std::uint32_t dispatcherContext = Allocate(4);
		if (record && context && dispatcherContext) {
			FillGuestMemory(record, 0, 80); FillGuestMemory(context, 0, 0x238);
			if (sourceRecord && IsRangeValid(sourceRecord, 20)) {
				std::uint32_t parameterCount = 0; Read(sourceRecord + 16, parameterCount);
				parameterCount = (std::min)(parameterCount, 15u);
				const std::uint32_t bytes = 20 + parameterCount * 4;
				if (IsRangeValid(sourceRecord, bytes)) CopyGuestMemory(record, sourceRecord, bytes);
			}
			Write(record, code);
			std::uint32_t recordFlags = 0; Read(record + 4, recordFlags);
			Write(record + 4, recordFlags | exceptionFlags);
			std::uint32_t recordAddress = 0; Read(record + 12, recordAddress);
			if (!recordAddress) Write(record + 12, exceptionAddress ? exceptionAddress : m_regs->eip);
			const std::uint32_t contextFlags = 0x00010007u; Write(context, contextFlags);
			Write(context + 0x208, m_regs->edi); Write(context + 0x20C, m_regs->esi);
			Write(context + 0x210, m_regs->ebx); Write(context + 0x214, m_regs->edx);
			Write(context + 0x218, m_regs->ecx); Write(context + 0x21C, m_regs->eax);
			Write(context + 0x220, m_regs->ebp); Write(context + 0x224, m_regs->eip);
			Write(context + 0x228, static_cast<std::uint32_t>(m_regs->cs));
			Write(context + 0x22C, m_regs->eflags); Write(context + 0x230, m_regs->esp);
			Write(context + 0x234, static_cast<std::uint32_t>(m_regs->ss));
			m_exceptionResume = *m_regs;
			m_exceptionPending = true;
			m_exceptionCode = code;
			m_exceptionRegistration = registration; m_exceptionRecord = record; m_exceptionContext = context;
			m_exceptionDispatcherContext = dispatcherContext; Write(dispatcherContext, registration);
			if (DeliverNextExceptionHandler()) return;
		} else { if (record) Free(record); if (context) Free(context); if (dispatcherContext) Free(dispatcherContext); }
	}
	if (m_logger) {
		char line[220] = {};
		sprintf_s(line, "[uwp-kernel:exception] %s gerou 0x%08X em EIP=0x%08X; execucao guest encerrada de forma controlada.\r\n",
			source, code, m_regs->eip);
		m_logger(line);
	}
	if (m_exceptionRecord) Free(m_exceptionRecord); if (m_exceptionContext) Free(m_exceptionContext);
	if (m_exceptionDispatcherContext) Free(m_exceptionDispatcherContext);
	for (const auto& frame : m_exceptionFrames) { if (frame.record) Free(frame.record); if (frame.context) Free(frame.context); if (frame.dispatcherContext) Free(frame.dispatcherContext); }
	m_exceptionFrames.clear(); m_exceptionRecord = m_exceptionContext = m_exceptionDispatcherContext = 0; m_exceptionPending = false;
	m_regs->eax = code;
	cpu_exit(m_cpu);
}

bool CxbxUwpKernelBridge::DeliverNextExceptionHandler()
{
	while (m_exceptionRegistration != 0xFFFFFFFFu && IsRangeValid(m_exceptionRegistration, 8)) {
		const std::uint32_t frame = m_exceptionRegistration;
		std::uint32_t next = 0xFFFFFFFFu, handler = 0;
		Read(frame, next); Read(frame + 4, handler); m_exceptionRegistration = next;
		if (!handler || !IsRangeValid(handler, 1)) continue;
		if (m_exceptionDispatcherContext) Write(m_exceptionDispatcherContext, next);
		*m_regs = m_exceptionResume;
		auto push = [this](std::uint32_t value) { m_regs->esp -= 4; Write(m_regs->esp, value); };
		push(m_exceptionDispatcherContext); push(m_exceptionContext); push(frame); push(m_exceptionRecord);
		push(StubBase + ExceptionReturnOrdinal * StubStride); m_regs->eip = handler;
		return true;
	}
	return false;
}

bool CxbxUwpKernelBridge::DeliverNextUnwindHandler()
{
	while (m_unwindRegistration != 0xFFFFFFFFu && m_unwindRegistration != m_unwindTargetFrame &&
		IsRangeValid(m_unwindRegistration, 8)) {
		const std::uint32_t frame = m_unwindRegistration;
		std::uint32_t next = 0xFFFFFFFFu, handler = 0;
		Read(frame, next); Read(frame + 4, handler); m_unwindRegistration = next;
		if (m_unwindResume.fs_hidden.base) Write(m_unwindResume.fs_hidden.base, next);
		if (!handler || !IsRangeValid(handler, 1)) continue;
		*m_regs = m_unwindResume;
		if (m_unwindDispatcherContext) Write(m_unwindDispatcherContext, m_unwindRegistration);
		auto push = [this](std::uint32_t value) { m_regs->esp -= 4; Write(m_regs->esp, value); };
		push(m_unwindDispatcherContext); push(m_unwindContext); push(frame); push(m_unwindRecord);
		push(StubBase + UnwindReturnOrdinal * StubStride); m_regs->eip = handler;
		return true;
	}
	*m_regs = m_unwindResume; m_regs->eax = m_unwindReturnValue;
	if (m_unwindTargetFrame && IsRangeValid(m_unwindTargetFrame, 8)) m_regs->esp = m_unwindTargetFrame + 8;
	if (m_unwindTargetIp && IsRangeValid(m_unwindTargetIp, 1)) m_regs->eip = m_unwindTargetIp;
	if (m_unwindOwnRecord && m_unwindRecord) Free(m_unwindRecord);
	if (m_unwindContext) Free(m_unwindContext);
	if (m_unwindDispatcherContext) Free(m_unwindDispatcherContext);
	m_unwindActive = false; m_unwindRecord = m_unwindContext = m_unwindDispatcherContext = 0; m_unwindRegistration = 0xFFFFFFFFu;
	return false;
}

void CxbxUwpKernelBridge::Unsupported(std::uint32_t ordinal)
{
	// Every public Xbox kernel ordinal has a dispatcher case.  Reaching this
	// helper means the guest supplied an unreadable stack/pointer.  Never guess
	// the calling convention here: popping zero arguments corrupts ESP for most
	// exports and was the source of delayed, apparently unrelated crashes.
	LogOrdinal("argumentos ou memoria guest invalidos", ordinal);
	RaiseGuestException(0xC0000005u, 0, "kernel ABI validation");
}

void CxbxUwpKernelBridge::Dispatch(std::uint32_t ordinal)
{
	m_lastDispatchedOrdinal = ordinal;
	m_lastDispatchEip = m_regs ? m_regs->eip : 0;
	++m_dispatchCount;
	bool firstOrdinal = false;
	if (ordinal < m_loggedDispatchOrdinals.size()) {
		firstOrdinal = !m_loggedDispatchOrdinals[ordinal];
		m_loggedDispatchOrdinals[ordinal] = true;
	}
	// Keep a compact startup trace and then log only the first observation of
	// each export. Repeated timing/string/memory calls no longer flood the file.
	if (m_logger && (m_dispatchCount <= 32 || firstOrdinal)) {
		std::uint32_t caller = 0;
		if (m_regs) Read(m_regs->esp, caller);
		char line[224] = {};
		sprintf_s(line, "[uwp-kernel:startup] chamada=%llu ordinal=%u caller=0x%08X EIP=0x%08X ESP=0x%08X.\r\n",
			static_cast<unsigned long long>(m_dispatchCount), ordinal,
			caller, m_regs ? m_regs->eip : 0, m_regs ? m_regs->esp : 0);
		m_logger(line);
	}
	const bool forceRomCrypto = ordinal >= CryptoRomBaseOrdinal && ordinal <= CryptoRomLastOrdinal;
	if (forceRomCrypto) ordinal = 335 + (ordinal - CryptoRomBaseOrdinal);
	CryptoOverrideGuard cryptoGuard(forceRomCrypto ? &m_cryptoOverrides : nullptr);
	std::uint32_t a = 0, b = 0, c = 0, d = 0;
	switch (ordinal) {
	case DpcReturnOrdinal:
		if (!m_dpcActive) { cpu_exit(m_cpu); break; }
		*m_regs = m_dpcResume; m_dpcActive = false; SetCurrentIrql(m_savedDpcIrql);
		if (!DeliverPendingInterrupt() && !DeliverPendingDpc() && !m_threads.empty()) {
			if (m_threads[m_currentThreadIndex].state != ThreadState::Running) SwitchThread(false);
			else DeliverPendingApc(m_threads[m_currentThreadIndex]);
		}
		break;
	case InterruptReturnOrdinal: {
		if (!m_interruptActive) { cpu_exit(m_cpu); break; }
		const std::uint32_t handled = m_regs->eax;
		if (m_activeInterrupt && IsRangeValid(m_activeInterrupt + 20, 4)) {
			std::uint32_t count = 0; Read(m_activeInterrupt + 20, count); Write(m_activeInterrupt + 20, count + 1);
		}
		InterruptFrame frame = {};
		if (m_interruptFrames.empty()) { cpu_exit(m_cpu); break; }
		frame = m_interruptFrames.back();
		m_interruptFrames.pop_back();
		*m_regs = frame.resume; m_regs->eax = handled; SetCurrentIrql(frame.irql);
		{
			std::lock_guard<std::mutex> lock(m_interruptMutex);
			auto active = m_interrupts.find(m_activeInterruptLevel);
			if (active != m_interrupts.end() && active->second.address == m_activeInterrupt) {
				active->second.inService = false;
				if ((active->second.assertedSources || active->second.pulsePending) &&
					(m_enabledInterrupts & (1u << m_activeInterruptLevel)) != 0 &&
					std::find(m_pendingInterrupts.begin(), m_pendingInterrupts.end(), m_activeInterruptLevel) == m_pendingInterrupts.end()) {
					m_pendingInterrupts.push_back(m_activeInterruptLevel);
				}
			}
		}
		m_interruptActive = frame.active;
		m_activeInterrupt = frame.address;
		m_activeInterruptLevel = frame.level;
		if (!DeliverPendingInterrupt() && !m_interruptActive && !DeliverPendingDpc() && !m_threads.empty()) {
			if (m_threads[m_currentThreadIndex].state != ThreadState::Running) SwitchThread(false);
			else DeliverPendingApc(m_threads[m_currentThreadIndex]);
		}
		break;
	}
	case SynchronizeReturnOrdinal: {
		if (!m_synchronizeActive) { cpu_exit(m_cpu); break; }
		const std::uint32_t result = m_regs->eax;
		*m_regs = m_synchronizeResume; m_regs->eax = result; m_synchronizeActive = false;
		SetCurrentIrql(m_savedSynchronizeIrql);
		if (!DeliverPendingInterrupt() && !DeliverPendingDpc() && !m_threads.empty())
			DeliverPendingApc(m_threads[m_currentThreadIndex]);
		break;
	}
	case ThreadReturnOrdinal:
		TerminateCurrentThread(m_regs->eax); break;
	case ApcReturnOrdinal: {
		if (m_threads.empty()) { cpu_exit(m_cpu); break; }
		auto& thread = m_threads[m_currentThreadIndex];
		if (!thread.deliveringApc) { cpu_exit(m_cpu); break; }
		if (thread.apcStage == 3 && thread.terminatingApcRundown) {
			const std::uint32_t exitStatus = thread.exitStatus;
			thread.deliveringApc = false; thread.terminatingApcRundown = false;
			thread.apcStage = 0; thread.activeApc = {}; TerminateCurrentThread(exitStatus); break;
		}
		if (thread.apcStage == 1 && thread.apcScratch) {
			std::uint32_t normal = 0, context = 0, argument1 = 0, argument2 = 0;
			Read(thread.apcScratch, normal); Read(thread.apcScratch + 4, context);
			Read(thread.apcScratch + 8, argument1); Read(thread.apcScratch + 12, argument2);
			if (normal && IsRangeValid(normal, 1) && (!thread.activeApc.userMode ||
				thread.alertable || thread.userApcDeliveryPending)) {
				SetCurrentIrql(thread.apcSavedIrql);
				auto push = [this](std::uint32_t value) { m_regs->esp -= 4; Write(m_regs->esp, value); };
				*m_regs = thread.apcResume; push(argument2); push(argument1); push(context);
				push(StubBase + ApcReturnOrdinal * StubStride); m_regs->eip = normal;
				thread.apcStage = 2; thread.regs = *m_regs; break;
			}
		}
		SetCurrentIrql(thread.apcSavedIrql);
		thread.regs = thread.apcResume; thread.deliveringApc = false;
		if (thread.activeApc.userMode) thread.userApcDeliveryPending = false;
		Write(thread.guestThread + 0x48, static_cast<std::uint8_t>(0));
		if (!thread.resumeWaitAfterApc) thread.alertable = false;
		thread.apcStage = 0; thread.apcScratch = 0; thread.activeApc = {};
		*m_regs = thread.regs;
		if (thread.resumeWaitAfterApc) {
			thread.resumeWaitAfterApc = false; thread.state = thread.apcInterruptedState;
			Write(thread.guestThread + 0x2C, static_cast<std::uint8_t>(5));
			SwitchThread(false);
		}
		break;
	}
	case TlsReturnOrdinal: {
		if (m_threads.empty()) { cpu_exit(m_cpu); break; }
		auto& thread = m_threads[m_currentThreadIndex];
		if (!thread.tlsCallbacksActive) { cpu_exit(m_cpu); break; }
		if (ContinueTlsCallbacks(thread)) { *m_regs = thread.regs; break; }
		*m_regs = thread.regs;
		if (thread.terminateAfterTls) { thread.terminateAfterTls = false; TerminateCurrentThread(thread.exitStatus); }
		break;
	}
	case ShutdownReturnOrdinal: {
		if (!m_shutdownNotificationActive) { cpu_exit(m_cpu); break; }
		if (ContinueShutdownNotifications()) break;
		const bool terminate = m_terminateAfterShutdownNotifications;
		m_terminateAfterShutdownNotifications = false;
		if (terminate) TerminateCurrentThread(StatusSuccess);
		break;
	}
	case DriverReturnOrdinal: {
		if (m_driverFrames.empty()) { cpu_exit(m_cpu); break; }
		const std::uint32_t status = m_regs->eax; DriverFrame frame = m_driverFrames.back(); m_driverFrames.pop_back();
		*m_regs = frame.resume;
		if (frame.irp && IsRangeValid(frame.irp + 0x18, 1) && status != 0x00000103u) Write(frame.irp + 0x10, status);
		if (frame.returnsStatus) m_regs->eax = status;
		if (frame.freeIrp && frame.irp && status == 0x00000103u) {
			const std::uint32_t eventAddress = Allocate(16);
			if (!eventAddress) { m_regs->eax = StatusNoMemory; break; }
			InitializeDispatcher(eventAddress, 0, 0);
			auto event = std::make_shared<KernelObject>(); event->kind = ObjectKind::Event; event->guestAddress = eventAddress; event->manualReset = true;
			{ std::lock_guard<std::mutex> lock(m_objectMutex); m_dispatcherObjects[eventAddress] = event; }
			Write(frame.irp + 0x20, eventAddress);
			auto& thread = m_threads[m_currentThreadIndex]; thread.pendingIrp = frame.irp;
			thread.pendingIrpInformationOut = frame.informationOut; thread.freePendingIrp = true;
			ScheduleWait({ event }, false, false, 0);
		} else {
			if (frame.informationOut && frame.irp && IsRangeValid(frame.irp + 0x14, 4)) { Read(frame.irp + 0x14, a); Write(frame.informationOut, a); }
			if (frame.freeIrp && frame.irp) Free(frame.irp);
		}
		break;
	}
	case ThreadNotifyReturnOrdinal:
		if (!m_threadNotifyActive) { cpu_exit(m_cpu); break; }
		*m_regs = m_threadNotifyResume; m_threadNotifyActive = false;
		DeliverThreadNotification(); break;
	case UnwindReturnOrdinal:
		if (!m_unwindActive) { cpu_exit(m_cpu); break; }
		if (m_regs->eax == 3 && m_unwindDispatcherContext) Read(m_unwindDispatcherContext, m_unwindRegistration);
		else if (m_regs->eax != 1) { RaiseGuestException(StatusInvalidDisposition, 0, "invalid unwind disposition", 0, ExceptionNoncontinuable); break; }
		DeliverNextUnwindHandler(); break;
	case ExceptionReturnOrdinal: {
		const std::uint32_t disposition = m_regs->eax;
		if (m_exceptionPending && disposition == 0) { // ExceptionContinueExecution
			std::uint32_t flags = 0; if (m_exceptionRecord) Read(m_exceptionRecord + 4, flags);
			if ((flags & ExceptionNoncontinuable) != 0) {
				RaiseGuestException(StatusNoncontinuableException, 0,
					"ExceptionContinueExecution em excecao nao continuavel", 0, ExceptionNoncontinuable);
				break;
			}
			regs_t restored = m_exceptionResume;
			if (m_exceptionContext && IsRangeValid(m_exceptionContext, 0x238)) {
				Read(m_exceptionContext + 0x208, restored.edi); Read(m_exceptionContext + 0x20C, restored.esi);
				Read(m_exceptionContext + 0x210, restored.ebx); Read(m_exceptionContext + 0x214, restored.edx);
				Read(m_exceptionContext + 0x218, restored.ecx); Read(m_exceptionContext + 0x21C, restored.eax);
				Read(m_exceptionContext + 0x220, restored.ebp); Read(m_exceptionContext + 0x224, restored.eip);
				std::uint32_t segment = 0; Read(m_exceptionContext + 0x228, segment); restored.cs = static_cast<decltype(restored.cs)>(segment);
				Read(m_exceptionContext + 0x22C, restored.eflags); Read(m_exceptionContext + 0x230, restored.esp);
				Read(m_exceptionContext + 0x234, segment); restored.ss = static_cast<decltype(restored.ss)>(segment);
			}
			*m_regs = restored; m_exceptionPending = false;
			if (m_exceptionRecord) Free(m_exceptionRecord); if (m_exceptionContext) Free(m_exceptionContext);
			if (m_exceptionDispatcherContext) Free(m_exceptionDispatcherContext);
			m_exceptionRecord = m_exceptionContext = m_exceptionDispatcherContext = 0; m_exceptionRegistration = 0xFFFFFFFFu;
			if (!m_exceptionFrames.empty()) { const ExceptionFrame previous = m_exceptionFrames.back(); m_exceptionFrames.pop_back(); m_exceptionResume = previous.resume; m_exceptionCode = previous.code; m_exceptionRegistration = previous.registration; m_exceptionRecord = previous.record; m_exceptionContext = previous.context; m_exceptionDispatcherContext = previous.dispatcherContext; m_exceptionPending = true; }
			if (m_logger) m_logger("[uwp-kernel:exception] Handler guest retomou a execucao.\r\n");
		} else if (m_exceptionPending && disposition == 1 && DeliverNextExceptionHandler()) {
			break;
		} else if (m_exceptionPending && disposition == 2) { // ExceptionNestedException
			std::uint32_t flags = 0; Read(m_exceptionRecord + 4, flags);
			Write(m_exceptionRecord + 4, flags | ExceptionNestedCall);
			if (m_exceptionDispatcherContext) {
				std::uint32_t nestedRegistration = 0;
				if (Read(m_exceptionDispatcherContext, nestedRegistration) && nestedRegistration != 0xFFFFFFFFu)
					m_exceptionRegistration = nestedRegistration;
			}
			if (DeliverNextExceptionHandler()) break;
			if (m_logger) m_logger("[uwp-kernel:exception] Excecao aninhada nao tratada; CPU encerrada.\r\n");
			m_exceptionPending = false;
			if (m_exceptionRecord) Free(m_exceptionRecord); if (m_exceptionContext) Free(m_exceptionContext);
			if (m_exceptionDispatcherContext) Free(m_exceptionDispatcherContext);
			m_exceptionRecord = m_exceptionContext = m_exceptionDispatcherContext = 0; m_exceptionRegistration = 0xFFFFFFFFu;
			for (const auto& frame : m_exceptionFrames) { if (frame.record) Free(frame.record); if (frame.context) Free(frame.context); if (frame.dispatcherContext) Free(frame.dispatcherContext); }
			m_exceptionFrames.clear(); m_regs->eax = m_exceptionCode; cpu_exit(m_cpu);
		} else {
			if (m_logger) m_logger("[uwp-kernel:exception] Handler guest nao tratou a excecao; CPU encerrada.\r\n");
			m_exceptionPending = false;
			if (m_exceptionRecord) Free(m_exceptionRecord); if (m_exceptionContext) Free(m_exceptionContext);
			if (m_exceptionDispatcherContext) Free(m_exceptionDispatcherContext);
			m_exceptionRecord = m_exceptionContext = m_exceptionDispatcherContext = 0; m_exceptionRegistration = 0xFFFFFFFFu;
			for (const auto& frame : m_exceptionFrames) { if (frame.record) Free(frame.record); if (frame.context) Free(frame.context); if (frame.dispatcherContext) Free(frame.dispatcherContext); } m_exceptionFrames.clear();
			m_regs->eax = m_exceptionCode; cpu_exit(m_cpu);
		}
		break;
	}
	case 1: // AvGetSavedDataAddress
		m_regs->eax = m_avSavedDataAddress; FinishStdcall(0); break;
	case 2: { // AvSendTVEncoderOption
		std::uint32_t option = 0, parameter = 0, result = 0;
		if (!ReadStack(0, a) || !ReadStack(1, option) || !ReadStack(2, parameter) ||
			!ReadStack(3, result)) return Unsupported(ordinal);
		if (result) {
			if (!IsRangeValid(result, 4)) return Unsupported(ordinal);
			switch (option) {
			case 5: Write(result, 0u); break;                 // AV_QUERY_CC_STATUS
			case 6: Write(result, 0x00400104u); break;        // HDTV, NTSC-M, 60 Hz
			case 13: Write(result, m_avCurrentMode); break;   // AV_OPTION_QUERY_MODE
			case 16: Write(result, 0u); break;                // Conexant encoder
			case 17: Write(result, 0u); break;                // AV_MODE_TABLE_VERSION
			default: break;
			}
		}
		FinishStdcall(4); break;
	}
	case 3: { // AvSetDisplayMode
		std::uint32_t step = 0, mode = 0, format = 0, pitch = 0, frameBuffer = 0;
		if (!ReadStack(0, a) || !ReadStack(1, step) || !ReadStack(2, mode) ||
			!ReadStack(3, format) || !ReadStack(4, pitch) || !ReadStack(5, frameBuffer))
			return Unsupported(ordinal);
		if (!mode) mode = 0x04010101u;
		m_avCurrentMode = mode;
		CxbxUwpConfigureNv2aDisplay(mode, format, pitch, frameBuffer);
		CxbxUwpWriteNv2aRegister(0x600800u, frameBuffer); // NV_PCRTC_START
		m_regs->eax = StatusSuccess; FinishStdcall(6); break;
	}
	case 4: // AvSetSavedDataAddress
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		m_avSavedDataAddress = a; FinishStdcall(1); break;
	case 5: // DbgBreakPoint
		RaiseGuestException(0x80000003u, 0, "DbgBreakPoint"); break;
	case 6: // DbgBreakPointWithStatus
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		RaiseGuestException(a ? a : 0x80000003u, 1, "DbgBreakPointWithStatus"); break;
	case 7: case 11: // DbgLoadImageSymbols / DbgUnLoadImageSymbols
		m_regs->eax = StatusSuccess; FinishStdcall(3); break;
	case 8: { // DbgPrint, cdecl: preserve caller-owned arguments.
		if (!ReadStack(0, a) || !IsRangeValid(a, 1)) return Unsupported(ordinal);
		std::string text;
		for (std::uint32_t cursor = a; text.size() < 1024; ++cursor) {
			std::uint8_t byte = 0; if (!Read(cursor, byte)) break;
			char ch = static_cast<char>(byte);
			if (!ch) break;
			text.push_back(ch);
		}
		if (m_logger) {
			std::string line = "[xbox:DbgPrint] " + text + "\r\n";
			m_logger(line.c_str());
		}
		m_regs->eax = static_cast<std::uint32_t>(text.size());
		FinishStdcall(0);
		break;
	}
	case 9: // HalReadSMCTrayState
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 4)) return Unsupported(ordinal);
		Write(a, 0x10u); if (b) Write(b, 0u); m_regs->eax = StatusSuccess; FinishStdcall(2); break;
	case 10: { // DbgPrompt (headless UWP)
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || (c && !IsRangeValid(b, c))) return Unsupported(ordinal);
		if (m_logger && a && IsRangeValid(a, 1)) {
			std::string prompt; for (std::uint32_t p = a; prompt.size() < 1024; ++p) { std::uint8_t ch = 0; if (!Read(p, ch) || !ch) break; prompt.push_back(static_cast<char>(ch)); }
			m_logger(("[xbox:DbgPrompt] " + prompt + "\r\n").c_str());
		}
		if (c) Write(b, static_cast<std::uint8_t>(0)); m_regs->eax = 0; FinishStdcall(3); break;
	}
	case 12: case 13: { // ExAcquireReadWriteLockExclusive / Shared
		if (!ReadStack(0, a) || !IsRangeValid(a, 0x34)) return Unsupported(ordinal);
		std::int32_t lockCount = -1; std::uint32_t writers = 0, readers = 0, entries = 0;
		Read(a, lockCount); Read(a + 4, writers); Read(a + 8, readers); Read(a + 12, entries);
		++lockCount; Write(a, lockCount);
		bool wait = false; ObjectPtr object;
		if (ordinal == 12) {
			wait = lockCount != 0;
			if (wait) { Write(a + 4, writers + 1); object = GetDispatcherObject(a + 0x10); }
		} else {
			wait = lockCount != 0 && (entries == 0 || writers != 0);
			if (wait) { Write(a + 8, readers + 1); object = GetDispatcherObject(a + 0x20); }
			else Write(a + 12, entries + 1);
		}
		// Statically allocated locks can reach here before their host-side
		// dispatcher mirrors have been registered. Reconstruct them from the
		// embedded Xbox dispatcher headers instead of letting the caller continue
		// without actually owning the lock.
		if (wait && !object) {
			const std::uint32_t address = a + (ordinal == 12 ? 0x10u : 0x20u);
			object = std::make_shared<KernelObject>();
			object->kind = ordinal == 12 ? ObjectKind::Event : ObjectKind::Semaphore;
			object->guestAddress = address;
			object->manualReset = false;
			std::int32_t signal = 0;
			Read(address + 4, signal);
			if (object->kind == ObjectKind::Semaphore) {
				object->count = signal;
				std::int32_t limit = INT_MAX;
				Read(address + 0x10, limit);
				object->limit = limit > 0 ? limit : INT_MAX;
			} else object->signaled = signal > 0;
			std::lock_guard<std::mutex> lock(m_objectMutex);
			m_dispatcherObjects[address] = object;
		}
		FinishStdcall(1);
		if (wait) ScheduleWait({ object }, false, false, 0);
		break;
	}
	case 14: // ExAllocatePool
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		m_regs->eax = Allocate(a); FinishStdcall(1); break;
	case 15: // ExAllocatePoolWithTag
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		m_regs->eax = Allocate(a); FinishStdcall(2); break;
	case 17: // ExFreePool
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		Free(a); m_regs->eax = 0; FinishStdcall(1); break;
	case 18: { // ExInitializeReadWriteLock
		if (!ReadStack(0, a) || !IsRangeValid(a, 0x34)) return Unsupported(ordinal);
		FillGuestMemory(a, 0, 0x34); Write(a, static_cast<std::int32_t>(-1));
		auto writer = std::make_shared<KernelObject>(); writer->kind = ObjectKind::Event; writer->guestAddress = a + 0x10;
		auto readers = std::make_shared<KernelObject>(); readers->kind = ObjectKind::Semaphore; readers->guestAddress = a + 0x20; readers->limit = INT_MAX;
		InitializeDispatcher(a + 0x10, 1, 0); InitializeDispatcher(a + 0x20, 5, 0); Write(a + 0x30, static_cast<std::int32_t>(INT_MAX));
		{ std::lock_guard<std::mutex> lock(m_objectMutex); m_dispatcherObjects[a + 0x10] = writer; m_dispatcherObjects[a + 0x20] = readers; }
		FinishStdcall(1); break;
	}
	case 19: { // ExInterlockedAddLargeInteger (LARGE_INTEGER by value)
		std::uint32_t low = 0, high = 0; if (!ReadStack(0, a) || !ReadStack(1, low) || !ReadStack(2, high) || !IsRangeValid(a, 8)) return Unsupported(ordinal);
		std::uint64_t old = 0; Read(a, old); const std::uint64_t increment = (static_cast<std::uint64_t>(high) << 32) | low;
		Write(a, old + increment); SetReturn64(old); FinishStdcall(4); break;
	}
	case 20: // ExInterlockedAddLargeStatistic, fastcall
		a = m_regs->ecx; b = m_regs->edx; if (!IsRangeValid(a, 8)) return Unsupported(ordinal);
		{ std::uint64_t value = 0; Read(a, value); Write(a, value + b); } FinishFastcall(); break;
	case 21: { // ExInterlockedCompareExchange64, fastcall
		a = m_regs->ecx; b = m_regs->edx; if (!ReadStack(0, c) || !IsRangeValid(a, 8) || !IsRangeValid(b, 8) || !IsRangeValid(c, 8)) return Unsupported(ordinal);
		std::uint64_t destination = 0, exchange = 0, comparand = 0; Read(a, destination); Read(b, exchange); Read(c, comparand);
		if (destination == comparand) Write(a, exchange); SetReturn64(destination); FinishFastcall(1); break;
	}
	case 23: // ExQueryPoolBlockSize
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		m_regs->eax = AllocationSize(a); FinishStdcall(1); break;
	case 24: { // ExQueryNonVolatileSetting
		std::uint32_t typeOut = 0, valueOut = 0, valueLength = 0, resultLengthOut = 0;
		if (!ReadStack(0, a) || !ReadStack(1, typeOut) || !ReadStack(2, valueOut) ||
			!ReadStack(3, valueLength) || !ReadStack(4, resultLengthOut)) return Unsupported(ordinal);
		auto found = m_nonVolatileSettings.find(a);
		if (found == m_nonVolatileSettings.end()) m_regs->eax = StatusObjectNameNotFound;
		else {
			const std::uint32_t required = static_cast<std::uint32_t>(found->second.size());
			if (resultLengthOut) Write(resultLengthOut, required);
			if (valueLength < required || !IsRangeValid(valueOut, required) || !IsRangeValid(typeOut, 4)) {
				m_regs->eax = StatusBufferTooSmall;
			} else {
				const bool binary = a == 1 || a == 4 || a == 0xFF || a == 0x100 ||
					a == 0x101 || a == 0x102 || a == 0xFFFE || a == 0xFFFF;
				Write(typeOut, binary ? 3u : 4u);
				FillGuestMemory(valueOut, 0, valueLength);
				if (required) std::memcpy(GuestPointer(valueOut, required), found->second.data(), required);
				m_regs->eax = StatusSuccess;
			}
		}
		FinishStdcall(5); break;
	}
	case 26: case 302: // ExRaiseException / RtlRaiseException
		if (!ReadStack(0, a) || !IsRangeValid(a, 20) || !Read(a, b)) return Unsupported(ordinal);
		RaiseGuestException(b, 1, ordinal == 26 ? "ExRaiseException" : "RtlRaiseException", a); break;
	case 25: // ExReadWriteRefurbInfo
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || b != m_refurbInfo.size() || !IsRangeValid(a, b)) { m_regs->eax = StatusInvalidParameter; FinishStdcall(3); break; }
		if (c) { std::memcpy(m_refurbInfo.data(), GuestPointer(a, b), b); const std::uint32_t signature = 0x52465242u; std::memcpy(m_refurbInfo.data(), &signature, 4); }
		else std::memcpy(GuestPointer(a, b), m_refurbInfo.data(), b);
		m_regs->eax = StatusSuccess; FinishStdcall(3); break;
	case 27: case 303: // ExRaiseStatus / RtlRaiseStatus
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		RaiseGuestException(a, 1, ordinal == 27 ? "ExRaiseStatus" : "RtlRaiseStatus", 0, ExceptionNoncontinuable); break;
	case 29: { // ExSaveNonVolatileSetting
		std::uint32_t type = 0, value = 0, length = 0;
		if (!ReadStack(0, a) || !ReadStack(1, type) || !ReadStack(2, value) ||
			!ReadStack(3, length) || !IsRangeValid(value, length)) return Unsupported(ordinal);
		if (type != 3 && type != 4) m_regs->eax = StatusInvalidParameter;
		else {
			auto& bytes = m_nonVolatileSettings[a];
			const auto* source = GuestPointer(value, length);
			bytes.assign(source, source + length);
			m_regs->eax = StatusSuccess;
		}
		FinishStdcall(4); break;
	}
	case 28: { // ExReleaseReadWriteLock
		if (!ReadStack(0, a) || !IsRangeValid(a, 0x34)) return Unsupported(ordinal);
		std::int32_t count = -1; std::uint32_t writers = 0, readers = 0, entries = 0;
		Read(a, count); Read(a + 4, writers); Read(a + 8, readers); Read(a + 12, entries); --count; Write(a, count);
		if (count == -1) Write(a + 12, 0u);
		else if (entries == 0 && readers) {
			Write(a + 12, readers); Write(a + 8, 0u); auto sem = GetDispatcherObject(a + 0x20);
			if (sem) { std::lock_guard<std::mutex> lock(m_objectMutex); sem->count += static_cast<std::int32_t>(readers); Write(a + 0x24, sem->count); m_objectChanged.notify_all(); }
		} else {
			if (entries) { --entries; Write(a + 12, entries); }
			if (!entries && writers) { Write(a + 4, writers - 1); auto event = GetDispatcherObject(a + 0x10); if (event) { std::lock_guard<std::mutex> lock(m_objectMutex); event->signaled = true; Write(a + 0x14, 1u); m_objectChanged.notify_all(); } }
		}
		FinishStdcall(1); WakeThreads(); SyncReadyList(); break;
	}
	case 32: case 33: { // ExfInterlockedInsertHeadList / TailList, fastcall
		a = m_regs->ecx; b = m_regs->edx; if (!IsRangeValid(a, 8) || !IsRangeValid(b, 8)) return Unsupported(ordinal);
		std::uint32_t first = 0, last = 0; Read(a, first); Read(a + 4, last); m_regs->eax = (ordinal == 32 ? first : last) == a ? 0 : (ordinal == 32 ? first : last);
		if (ordinal == 32) { Write(b, first); Write(b + 4, a); Write(first + 4, b); Write(a, b); }
		else { Write(b, a); Write(b + 4, last); Write(last, b); Write(a + 4, b); }
		FinishFastcall(); break;
	}
	case 34: { // ExfInterlockedRemoveHeadList, fastcall
		a = m_regs->ecx; if (!IsRangeValid(a, 8)) return Unsupported(ordinal); std::uint32_t first = 0, next = 0; Read(a, first);
		if (first == a) m_regs->eax = 0; else { Read(first, next); Write(a, next); Write(next + 4, a); m_regs->eax = first; }
		FinishFastcall(); break;
	}
	case 35: m_regs->eax = m_fscCachePages; FinishStdcall(0); break;
	case 36: // FscInvalidateIdleBlocks: brokered I/O is uncached; invalidate enumeration cursors.
		for (auto& object : m_handles) if (object.second && object.second->findHandle != INVALID_HANDLE_VALUE) { FindClose(object.second->findHandle); object.second->findHandle = INVALID_HANDLE_VALUE; object.second->findMask.clear(); }
		FinishStdcall(0); break;
	case 37: if (!ReadStack(0, a)) return Unsupported(ordinal); if (a > 2048) m_regs->eax = StatusInvalidParameter; else { m_fscCachePages = a; m_regs->eax = StatusSuccess; } FinishStdcall(1); break;
	case 51: { // InterlockedCompareExchange, fastcall (ECX, EDX, stack)
		a = m_regs->ecx; b = m_regs->edx;
		if (!ReadStack(0, c) || !Read(a, d)) return Unsupported(ordinal);
		m_regs->eax = d;
		if (d == c) Write(a, b);
		FinishFastcall(1); break;
	}
	case 52: case 53: { // InterlockedDecrement / Increment
		a = m_regs->ecx;
		if (!Read(a, b)) return Unsupported(ordinal);
		b = ordinal == 52 ? b - 1 : b + 1;
		Write(a, b); m_regs->eax = b; FinishFastcall(); break;
	}
	case 54: case 55: { // InterlockedExchange / ExchangeAdd
		a = m_regs->ecx; b = m_regs->edx;
		if (!Read(a, c)) return Unsupported(ordinal);
		Write(a, ordinal == 54 ? b : c + b);
		m_regs->eax = c; FinishFastcall(); break;
	}
	case 92: case 93: { // KeAlertResumeThread / KeAlertThread
		if (!ReadStack(0, a)) return Unsupported(ordinal); auto* thread = FindThreadByHandle(a);
		if (!thread) m_regs->eax = StatusInvalidHandle; else {
			thread->alerted[0] = true; Write(thread->guestThread + 0x2D, static_cast<std::uint8_t>(1));
			if (ordinal == 92) { if (!ReadStack(1, b)) return Unsupported(ordinal); if (b) Write(b, thread->suspendCount); if (thread->suspendCount) --thread->suspendCount; Write(thread->guestThread + 0x75, static_cast<std::uint8_t>(thread->suspendCount)); if (!thread->suspendCount) { Write(thread->guestThread + 0xF4, 1u); Write(thread->guestThread + 0xCB, static_cast<std::uint8_t>(0)); if (thread->state == ThreadState::Suspended) { thread->state = ThreadState::Runnable; Write(thread->guestThread + 0x2C, static_cast<std::uint8_t>(1)); } } }
			m_regs->eax = StatusSuccess;
		}
		WakeThreads(); SyncReadyList(); FinishStdcall(ordinal == 92 ? 2 : 1); break;
	}
	case 94: // KeBoostPriorityThread
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a + 0x32, 0x42)) return Unsupported(ordinal);
		{ std::int8_t priority = 0; std::uint8_t disableBoost = 0; Read(a + 0x32, priority); Read(a + 0x73, disableBoost); if (!disableBoost) { priority = static_cast<std::int8_t>((std::min)(31, static_cast<int>(priority) + static_cast<int>(static_cast<std::int32_t>(b)))); Write(a + 0x32, priority); if (auto* thread = FindThreadByGuestAddress(a)) thread->priority = priority; } }
		m_regs->eax = StatusSuccess; FinishStdcall(2); break;
	case 95: case 96: { // KeBugCheck / KeBugCheckEx
		if (!ReadStack(0, a)) return Unsupported(ordinal); if (m_logger) { char line[96] = {}; sprintf_s(line, "[uwp-kernel:bugcheck] 0x%08X.\r\n", a); m_logger(line); }
		FinishStdcall(ordinal == 95 ? 1 : 5); TerminateCurrentThread(a); break;
	}
	case 97: { // KeCancelTimer
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		auto object = GetDispatcherObject(a);
		m_regs->eax = object && object->timerActive ? 1 : 0;
		if (object) { std::lock_guard<std::mutex> lock(m_objectMutex); object->timerActive = false; object->signaled = false; Write(a + 3, static_cast<std::uint8_t>(0)); SyncDispatcherSignal(object); }
		FinishStdcall(1); break;
	}
	case 99: { // KeDelayExecutionThread
		if (!ReadStack(0, c) || !ReadStack(1, b) || !ReadStack(2, a)) return Unsupported(ordinal);
		if (c > 1) { m_regs->eax = StatusInvalidParameter; FinishStdcall(3); break; }
		FinishStdcall(3); ScheduleDelay(a, b != 0, static_cast<std::uint8_t>(c), 4); break;
	}
	case 105: { // KeInitializeApc
		if (!ReadStack(0, a) || !IsRangeValid(a, 40)) return Unsupported(ordinal);
		std::uint32_t thread = 0, kernel = 0, rundown = 0, normal = 0, mode = 0, context = 0;
		if (!ReadStack(1, thread) || !ReadStack(2, kernel) || !ReadStack(3, rundown) ||
			!ReadStack(4, normal) || !ReadStack(5, mode) || !ReadStack(6, context)) return Unsupported(ordinal);
		FillGuestMemory(a, 0, 40); Write(a, static_cast<std::uint16_t>(0x12));
		Write(a + 2, static_cast<std::uint8_t>(normal ? mode : 0)); Write(a + 4, thread);
		Write(a + 0x10, kernel); Write(a + 0x14, rundown); Write(a + 0x18, normal); Write(a + 0x1C, normal ? context : 0u);
		FinishStdcall(7); break;
	}
	case 106: // KeInitializeDeviceQueue
		if (!ReadStack(0, a) || !IsRangeValid(a, 12)) return Unsupported(ordinal);
		FillGuestMemory(a, 0, 12); Write(a, static_cast<std::int16_t>(0x14)); Write(a + 2, static_cast<std::uint8_t>(12)); Write(a + 3, static_cast<std::uint8_t>(0)); Write(a + 4, a + 4); Write(a + 8, a + 4); FinishStdcall(1); break;
	case 101: { // KeEnterCriticalRegion
		auto& thread = m_threads[m_currentThreadIndex];
		// Xbox/NT uses a signed disable count: entering decrements it and leaving
		// increments it back to zero.  Keeping a positive nesting count made the
		// host scheduler work internally but exposed the opposite ABI value in
		// KTHREAD and could let guest kernel code make the wrong APC decision.
		if (thread.kernelApcDisable > INT_MIN) --thread.kernelApcDisable;
		Write(thread.guestThread + 0x68, static_cast<std::uint32_t>(thread.kernelApcDisable));
		FinishStdcall(0); break;
	}
	case 122: { // KeLeaveCriticalRegion
		auto& thread = m_threads[m_currentThreadIndex];
		if (thread.kernelApcDisable < 0) ++thread.kernelApcDisable;
		Write(thread.guestThread + 0x68, static_cast<std::uint32_t>(thread.kernelApcDisable));
		FinishStdcall(0);
		if (thread.kernelApcDisable == 0) DeliverPendingApc(thread);
		break;
	}
	case 108: { // KeInitializeEvent
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) ||
			!IsRangeValid(a, 0x10) || b > 1) return Unsupported(ordinal);
		auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::Event;
		object->guestAddress = a; object->manualReset = b == 0; object->signaled = c != 0;
		InitializeDispatcher(a, static_cast<std::uint8_t>(b == 0 ? 0 : 1), object->signaled ? 1 : 0);
		{ std::lock_guard<std::mutex> lock(m_objectMutex); m_dispatcherObjects[a] = object; }
		FinishStdcall(3); break;
	}
	case 110: { // KeInitializeMutant
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 0x20)) return Unsupported(ordinal);
		auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::Mutant; object->guestAddress = a; object->signaled = b == 0;
		if (b) { object->ownerThreadId = m_threads[m_currentThreadIndex].id; object->recursionCount = 1; }
		InitializeDispatcher(a, 2, object->signaled ? 1 : 0);
		Write(a + 0x10, a + 0x10); Write(a + 0x14, a + 0x10);
		Write(a + 0x18, b ? m_currentThread : 0u); Write(a + 0x1C, static_cast<std::uint8_t>(0));
		if (b) LinkMutantToThread(object, &m_threads[m_currentThreadIndex]);
		{ std::lock_guard<std::mutex> lock(m_objectMutex); m_dispatcherObjects[a] = object; }
		FinishStdcall(2); break;
	}
	case 111: { // KeInitializeQueue
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 40)) return Unsupported(ordinal);
		auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::Queue; object->guestAddress = a;
		InitializeDispatcher(a, 4, 0); Write(a + 16, a + 16); Write(a + 20, a + 16); Write(a + 24, 0u); Write(a + 28, b > 1 ? b : 1u); Write(a + 32, a + 32); Write(a + 36, a + 32);
		{ std::lock_guard<std::mutex> lock(m_objectMutex); m_dispatcherObjects[a] = object; } FinishStdcall(2); break;
	}
	case 112: { // KeInitializeSemaphore
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) ||
			!IsRangeValid(a, 0x14) || static_cast<std::int32_t>(b) < 0 ||
			static_cast<std::int32_t>(c) <= 0 || static_cast<std::int32_t>(b) > static_cast<std::int32_t>(c))
			return Unsupported(ordinal);
		auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::Semaphore;
		object->guestAddress = a; object->count = static_cast<std::int32_t>(b); object->limit = static_cast<std::int32_t>(c);
		InitializeDispatcher(a, 5, object->count); Write(a + 16, object->limit);
		{ std::lock_guard<std::mutex> lock(m_objectMutex); m_dispatcherObjects[a] = object; }
		FinishStdcall(3); break;
	}
	case 113: { // KeInitializeTimerEx
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 0x28) || b > 1)
			return Unsupported(ordinal);
		auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::Timer; object->guestAddress = a; object->manualReset = b == 0;
		InitializeDispatcher(a, static_cast<std::uint8_t>(b == 0 ? 8 : 9), 0);
		Write(a + 0x10, 0u); Write(a + 0x14, 0u); // TimerListEntry is not inserted.
		Write(a + 0x18, static_cast<std::uint64_t>(0));
		Write(a + 0x20, 0u); Write(a + 0x24, 0u);
		{ std::lock_guard<std::mutex> lock(m_objectMutex); m_dispatcherObjects[a] = object; }
		FinishStdcall(2); break;
	}
	case 114: case 115: { // KeInsertByKeyDeviceQueue / KeInsertDeviceQueue
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 12) || !IsRangeValid(b, 13)) return Unsupported(ordinal);
		if (ordinal == 114 && !ReadStack(2, c)) return Unsupported(ordinal); if (ordinal == 114) Write(b + 8, c);
		std::uint8_t busy = 0; Read(a + 3, busy); bool inserted = busy != 0;
		if (!inserted) Write(a + 3, static_cast<std::uint8_t>(1)); else {
			std::uint32_t before = a + 4;
			if (ordinal == 114) { Read(a + 4, before); while (before != a + 4) { std::uint32_t key = 0, next = 0; Read(before + 8, key); if (c < key) break; Read(before, next); before = next; } }
			std::uint32_t previous = 0; Read(before + 4, previous); Write(b, before); Write(b + 4, previous); Write(previous, b); Write(before + 4, b);
		}
		Write(b + 12, static_cast<std::uint8_t>(inserted)); m_regs->eax = inserted ? 1 : 0; FinishStdcall(ordinal == 114 ? 3 : 2); break;
	}
	case 116: case 117: { // KeInsertHeadQueue / KeInsertQueue
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 40) || !IsRangeValid(b, 8)) return Unsupported(ordinal);
		std::uint32_t signal = 0, first = 0, last = 0; Read(a + 4, signal); Read(a + 16, first); Read(a + 20, last); m_regs->eax = signal;
		if (ordinal == 116) { Write(b, first); Write(b + 4, a + 16); Write(first + 4, b); Write(a + 16, b); }
		else { Write(b, a + 16); Write(b + 4, last); Write(last, b); Write(a + 20, b); }
		Write(a + 4, signal + 1); auto object = GetDispatcherObject(a); if (object) { std::lock_guard<std::mutex> lock(m_objectMutex); object->signaled = true; m_objectChanged.notify_all(); }
		FinishStdcall(2); WakeThreads(); SyncReadyList(); break;
	}
	case 118: { // KeInsertQueueApc
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(a, 40)) return Unsupported(ordinal);
		std::uint32_t threadAddress = 0, kernelRoutine = 0, normalRoutine = 0, context = 0;
		if (!Read(a + 4, threadAddress) || !Read(a + 0x10, kernelRoutine) || !Read(a + 0x18, normalRoutine) || !Read(a + 0x1C, context)) return Unsupported(ordinal);
		auto* thread = FindThreadByGuestAddress(threadAddress);
		if (!thread || (!normalRoutine && !kernelRoutine)) m_regs->eax = 0;
		else { std::uint8_t mode = 0, inserted = 0; std::uint32_t rundown = 0; Read(a + 2, mode); Read(a + 3, inserted); Read(a + 0x14, rundown); if (inserted || mode > 1) m_regs->eax = 0; else {
			const std::uint32_t head = thread->guestThread + (mode ? 0x3C : 0x34);
			std::uint32_t tail = head; Read(head + 4, tail); if (!IsRangeValid(tail, 8)) tail = head;
			Write(a + 8, head); Write(a + 12, tail); Write(tail, a + 8); Write(head + 4, a + 8);
			thread->apcs.push_back({ a, kernelRoutine, rundown, normalRoutine, context, b, c, mode != 0 });
			Write(a + 3, static_cast<std::uint8_t>(1)); Write(thread->guestThread + (mode ? 0x4A : 0x49), static_cast<std::uint8_t>(1)); m_regs->eax = 1;
		} }
		FinishStdcall(4); break;
	}
	case 123: { // KePulseEvent
		std::uint32_t increment = 0, wait = 0;
		if (!ReadStack(0, a) || !ReadStack(1, increment) || !ReadStack(2, wait)) return Unsupported(ordinal); auto object = GetDispatcherObject(a);
		if (!object || object->kind != ObjectKind::Event) { m_regs->eax = 0; FinishStdcall(3); break; }
		m_regs->eax = PulseEventObject(object);
		if (increment) {
			for (auto& candidate : m_threads) if (candidate.state == ThreadState::Waiting &&
				std::find(candidate.waitObjects.begin(), candidate.waitObjects.end(), object) != candidate.waitObjects.end()) {
				candidate.priority = (std::min<std::int32_t>)(31, candidate.priority + static_cast<std::int32_t>(increment));
				candidate.quantumRemaining = candidate.quantum;
				Write(candidate.guestThread + 0x32, static_cast<std::uint8_t>(candidate.priority));
			}
		}
		WakeThreads(); SyncReadyList();
		if (wait && m_currentThreadIndex < m_threads.size()) {
			Write(m_threads[m_currentThreadIndex].guestThread + 0x56, static_cast<std::uint8_t>(1));
			Write(m_threads[m_currentThreadIndex].guestThread + 0x54, m_currentIrql);
		}
		FinishStdcall(3); break;
	}
	case 124: // KeQueryBasePriorityThread
		if (!ReadStack(0, a) || !IsRangeValid(a + 0x70, 1)) return Unsupported(ordinal);
		{ std::uint8_t priority = 0; Read(a + 0x70, priority); m_regs->eax = static_cast<std::uint32_t>(static_cast<std::int32_t>(static_cast<std::int8_t>(priority))); } FinishStdcall(1); break;
	case 131: { // KeReleaseMutant
		std::uint32_t increment = 0, abandoned = 0, wait = 0;
		if (!ReadStack(0, a) || !ReadStack(1, increment) || !ReadStack(2, abandoned) ||
			!ReadStack(3, wait)) return Unsupported(ordinal); auto object = GetDispatcherObject(a);
		if (!object || object->kind != ObjectKind::Mutant) return Unsupported(ordinal);
		{
			std::lock_guard<std::mutex> lock(m_objectMutex);
			std::int32_t previous = 0; Read(a + 4, previous); m_regs->eax = static_cast<std::uint32_t>(previous);
			const std::uint32_t threadId = m_threads[m_currentThreadIndex].id;
			if (object->ownerThreadId != threadId && !abandoned) {
				RaiseGuestException(0xC0000046u, 0, "KeReleaseMutant"); break;
			}
			object->abandoned = abandoned != 0;
			if (object->recursionCount > 1 && !abandoned) {
				--object->recursionCount; Write(a + 4, previous + 1);
			} else {
				object->recursionCount = 0; object->ownerThreadId = 0; object->signaled = true;
				UnlinkMutant(object);
				Write(a + 4, 1u); Write(a + 0x18, 0u);
				Write(a + 0x1C, static_cast<std::uint8_t>(object->abandoned));
			}
		}
		(void)increment;
		if (wait && m_currentThreadIndex < m_threads.size()) {
			Write(m_threads[m_currentThreadIndex].guestThread + 0x56, static_cast<std::uint8_t>(1));
			Write(m_threads[m_currentThreadIndex].guestThread + 0x54, m_currentIrql);
		}
		m_objectChanged.notify_all(); WakeThreads(); SyncReadyList(); FinishStdcall(4); break;
	}
	case 132: { // KeReleaseSemaphore
		std::uint32_t increment = 0, adjustment = 0, wait = 0;
		if (!ReadStack(0, a) || !ReadStack(1, increment) || !ReadStack(2, adjustment) ||
			!ReadStack(3, wait)) return Unsupported(ordinal); auto object = GetDispatcherObject(a);
		if (!object || object->kind != ObjectKind::Semaphore) return Unsupported(ordinal);
		const std::int64_t adjusted = static_cast<std::int64_t>(object->count) + static_cast<std::int32_t>(adjustment);
		if (adjusted > object->limit || adjusted < object->count) {
			RaiseGuestException(0xC0000047u, 4, "KeReleaseSemaphore"); break;
		}
		{ std::lock_guard<std::mutex> lock(m_objectMutex); c = object->count; object->count = static_cast<std::int32_t>(adjusted); Write(a + 4, object->count); }
		if (c == 0 && increment) {
			for (auto& candidate : m_threads) if (candidate.state == ThreadState::Waiting &&
				std::find(candidate.waitObjects.begin(), candidate.waitObjects.end(), object) != candidate.waitObjects.end()) {
				candidate.priority = (std::min<std::int32_t>)(31, candidate.priority + static_cast<std::int32_t>(increment));
				candidate.quantumRemaining = candidate.quantum;
				Write(candidate.guestThread + 0x32, static_cast<std::uint8_t>(candidate.priority));
			}
		}
		m_objectChanged.notify_all(); WakeThreads(); SyncReadyList();
		if (wait && m_currentThreadIndex < m_threads.size()) {
			Write(m_threads[m_currentThreadIndex].guestThread + 0x56, static_cast<std::uint8_t>(1));
			Write(m_threads[m_currentThreadIndex].guestThread + 0x54, m_currentIrql);
		}
		m_regs->eax = c; FinishStdcall(4); break;
	}
	case 133: case 134: { // KeRemoveByKeyDeviceQueue / KeRemoveDeviceQueue
		if (!ReadStack(0, a) || !IsRangeValid(a, 12)) return Unsupported(ordinal); if (ordinal == 133 && !ReadStack(1, b)) return Unsupported(ordinal);
		std::uint32_t entry = 0; Read(a + 4, entry);
		if (entry == a + 4) { Write(a + 3, static_cast<std::uint8_t>(0)); m_regs->eax = 0; }
		else {
			if (ordinal == 133) { std::uint32_t cursor = entry; while (cursor != a + 4) { std::uint32_t key = 0, next = 0; Read(cursor + 8, key); if (b <= key) { entry = cursor; break; } Read(cursor, next); cursor = next; if (cursor == a + 4) { Read(a + 4, entry); break; } } }
			std::uint32_t next = 0, previous = 0; Read(entry, next); Read(entry + 4, previous); Write(previous, next); Write(next + 4, previous); Write(entry + 12, static_cast<std::uint8_t>(0)); m_regs->eax = entry;
		}
		FinishStdcall(ordinal == 133 ? 2 : 1); break;
	}
	case 135: { // KeRemoveEntryDeviceQueue
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 12) || !IsRangeValid(b, 13)) return Unsupported(ordinal); std::uint8_t inserted = 0; Read(b + 12, inserted); m_regs->eax = inserted;
		if (inserted) { std::uint32_t next = 0, previous = 0; Read(b, next); Read(b + 4, previous); Write(previous, next); Write(next + 4, previous); Write(b + 12, static_cast<std::uint8_t>(0)); }
		FinishStdcall(2); break;
	}
	case 136: { // KeRemoveQueue
		std::uint32_t waitMode = 0;
		if (!ReadStack(0, a) || !ReadStack(1, waitMode) || !ReadStack(2, b) ||
			waitMode > 1 || !IsRangeValid(a, 40)) return Unsupported(ordinal); auto object = GetDispatcherObject(a); if (!object || object->kind != ObjectKind::Queue) return Unsupported(ordinal);
		auto& thread = m_threads[m_currentThreadIndex];
		const std::uint32_t queueEntry = thread.guestThread + 0x7C;
		if (thread.associatedQueue != a) {
			if (thread.associatedQueue) {
				std::uint32_t oldCount = 0; Read(thread.associatedQueue + 0x18, oldCount); if (oldCount) Write(thread.associatedQueue + 0x18, oldCount - 1);
				std::uint32_t next = 0, previous = 0;
				if (Read(queueEntry, next) && Read(queueEntry + 4, previous) && next && previous && IsRangeValid(next, 8) && IsRangeValid(previous, 8)) { Write(previous, next); Write(next + 4, previous); }
			}
			const std::uint32_t head = a + 32; std::uint32_t tail = head; Read(head + 4, tail); if (!IsRangeValid(tail, 8)) tail = head;
			Write(queueEntry, head); Write(queueEntry + 4, tail); Write(tail, queueEntry); Write(head + 4, queueEntry);
			thread.associatedQueue = a; Write(thread.guestThread + 0x78, a);
		} else {
			std::uint32_t current = 0; Read(a + 0x18, current); if (current) Write(a + 0x18, current - 1);
		}
		std::uint32_t first = 0, signal = 0, current = 0, maximum = 0;
		Read(a + 16, first); Read(a + 4, signal); Read(a + 0x18, current); Read(a + 0x1C, maximum);
		if (first != a + 16 && current < maximum) {
			std::uint32_t next = 0; Read(first, next); Write(a + 16, next); Write(next + 4, a + 16);
			if (signal) Write(a + 4, signal - 1); Write(a + 0x18, current + 1);
			object->signaled = signal > 1; m_regs->eax = first; FinishStdcall(3);
		} else {
			FinishStdcall(3); thread.queueWait = a;
			ScheduleWait({ object }, false, false, b, static_cast<std::uint8_t>(waitMode), 0);
		}
		break;
	}
	case 138: { // KeResetEvent
		if (!ReadStack(0, a)) return Unsupported(ordinal); auto object = GetDispatcherObject(a);
		if (!object) return Unsupported(ordinal);
		{ std::lock_guard<std::mutex> lock(m_objectMutex); b = object->signaled ? 1 : 0; object->signaled = false; Write(a + 4, 0u); }
		m_regs->eax = b; FinishStdcall(1); break;
	}
	case 139: { // KeRestoreFloatingPointState
		if (!ReadStack(0, a) || !IsRangeValid(a, 32)) return Unsupported(ordinal);
		// KFLOATING_SAVE is not an FNSAVE image. Cxbx's kernel contract only
		// restores precision and rounding; StatusWord, pointers and CR0 are not
		// guest processor state to restore from this public structure.
		std::uint32_t savedControl = 0;
		if (!Read(a, savedControl)) return Unsupported(ordinal);
		constexpr std::uint16_t PrecisionAndRoundingMask = 0x0F00;
		const std::uint16_t control = static_cast<std::uint16_t>(
			(m_regs->fctrl & ~PrecisionAndRoundingMask) |
			(savedControl & PrecisionAndRoundingMask));
		write_fctrl(m_cpu, control);
		m_regs->eax = StatusSuccess; FinishStdcall(1); break;
	}
	case 140: { // KeResumeThread
		if (!ReadStack(0, a)) return Unsupported(ordinal); auto* thread = FindThreadByGuestAddress(a);
		if (!thread) m_regs->eax = 0; else {
			m_regs->eax = thread->suspendCount;
			if (thread->suspendCount) --thread->suspendCount;
			Write(thread->guestThread + 0x75, static_cast<std::uint8_t>(thread->suspendCount));
			if (!thread->suspendCount) { Write(thread->guestThread + 0xF4, 1u); Write(thread->guestThread + 0xCB, static_cast<std::uint8_t>(0)); if (thread->state == ThreadState::Suspended) { thread->state = ThreadState::Runnable; Write(thread->guestThread + 0x2C, static_cast<std::uint8_t>(1)); } }
		}
		WakeThreads(); SyncReadyList(); FinishStdcall(1); break;
	}
	case 141: // KeRundownQueue
		if (!ReadStack(0, a) || !IsRangeValid(a, 40)) return Unsupported(ordinal);
		{ std::uint32_t first = 0; Read(a + 16, first); m_regs->eax = first == a + 16 ? 0 : a + 16;
			for (auto& thread : m_threads) if (thread.associatedQueue == a) {
				thread.queueWait = 0; thread.associatedQueue = 0; Write(thread.guestThread + 0x78, 0u);
				Write(thread.guestThread + 0x7C, thread.guestThread + 0x7C); Write(thread.guestThread + 0x80, thread.guestThread + 0x7C);
			}
			Write(a + 32, a + 32); Write(a + 36, a + 32); }
		FinishStdcall(1); break;
	case 142: { // KeSaveFloatingPointState
		if (!ReadStack(0, a) || !IsRangeValid(a, 32)) return Unsupported(ordinal);
		// Match the legacy kernel implementation: only ControlWord is meaningful
		// and the remaining public fields are returned clean. Kernel floating-point
		// work then uses double precision and round-to-nearest without changing the
		// caller's exception masks.
		Write(a, static_cast<std::uint32_t>(m_regs->fctrl));
		for (std::uint32_t offset = 4; offset < 32; offset += 4) Write(a + offset, 0u);
		constexpr std::uint16_t PrecisionAndRoundingMask = 0x0F00;
		constexpr std::uint16_t DoublePrecisionRoundNearest = 0x0200;
		write_fctrl(m_cpu, static_cast<std::uint16_t>(
			(m_regs->fctrl & ~PrecisionAndRoundingMask) | DoublePrecisionRoundNearest));
		m_regs->eax = StatusSuccess; FinishStdcall(1); break;
	}
	case 143: { // KeSetBasePriorityThread
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a + 0x70, 3)) return Unsupported(ordinal);
		auto* thread = FindThreadByGuestAddress(a);
		if (!thread) { m_regs->eax = 0; FinishStdcall(2); break; }
		m_regs->eax = static_cast<std::uint32_t>(static_cast<std::int32_t>(thread->basePriority));
		thread->basePriority = static_cast<std::int8_t>(b);
		Write(thread->guestThread + 0x70, thread->basePriority);
		std::uint8_t priorityDecrement = 0;
		Read(thread->guestThread + 0x72, priorityDecrement);
		if (priorityDecrement == 0) {
			thread->priority = thread->basePriority;
			Write(thread->guestThread + 0x32, thread->priority);
		}
		FinishStdcall(2); break;
	}
	case 144: // KeSetDisableBoostThread
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a + 0x73, 1)) return Unsupported(ordinal);
		{ std::uint8_t previous = 0; Read(a + 0x73, previous); Write(a + 0x73, static_cast<std::uint8_t>(b != 0)); m_regs->eax = previous; } FinishStdcall(2); break;
	case 145: case 146: { // KeSetEvent / KeSetEventBoostPriority
		if (!ReadStack(0, a)) return Unsupported(ordinal); auto object = GetDispatcherObject(a);
		if (!object) return Unsupported(ordinal);
		std::uint32_t awakenedThread = 0;
		ThreadContext* selectedThread = nullptr;
		if (ordinal == 146) {
			if (!ReadStack(1, b) || (b && !IsRangeValid(b, 4))) return Unsupported(ordinal);
			for (auto& candidate : m_threads) {
				if (candidate.state != ThreadState::Waiting) continue;
				if (std::find(candidate.waitObjects.begin(), candidate.waitObjects.end(), object) == candidate.waitObjects.end()) continue;
				awakenedThread = candidate.guestThread;
				selectedThread = &candidate;
				candidate.quantumRemaining = 60;
				Write(candidate.guestThread + 0x6C, candidate.quantumRemaining);
				break;
			}
			if (b) Write(b, awakenedThread);
		}
		std::uint32_t increment = 0, wait = 0;
		if (ordinal == 145 && (!ReadStack(1, increment) || !ReadStack(2, wait))) return Unsupported(ordinal);
		if (ordinal == 145) {
			for (auto& candidate : m_threads) {
				if (candidate.state != ThreadState::Waiting ||
					std::find(candidate.waitObjects.begin(), candidate.waitObjects.end(), object) == candidate.waitObjects.end()) continue;
				std::uint8_t disableBoost = 0; Read(candidate.guestThread + 0x73, disableBoost);
				if (!disableBoost && increment) {
					candidate.priority = static_cast<std::int8_t>((std::min)(31,
						static_cast<int>(candidate.priority) + static_cast<int>(static_cast<std::int32_t>(increment))));
					Write(candidate.guestThread + 0x32, candidate.priority);
				}
			}
		} else if (selectedThread) {
			std::uint8_t disableBoost = 0; Read(selectedThread->guestThread + 0x73, disableBoost);
			if (!disableBoost) {
				selectedThread->priority = static_cast<std::int8_t>((std::min)(31,
					static_cast<int>(selectedThread->priority) + 1));
				Write(selectedThread->guestThread + 0x32, selectedThread->priority);
			}
		}
		const bool originalManualReset = object->manualReset;
		{ std::lock_guard<std::mutex> lock(m_objectMutex); b = object->signaled ? 1 : 0;
			object->signaled = true;
			// KeSetEventBoostPriority satisfies exactly the first waiter instead of
			// leaving a notification event signalled for every waiter.
			if (ordinal == 146 && selectedThread) object->manualReset = false;
			SyncDispatcherSignal(object);
		}
		if (ordinal == 145 && wait && m_currentThreadIndex < m_threads.size()) {
			auto& current = m_threads[m_currentThreadIndex];
			Write(current.guestThread + 0x56, static_cast<std::uint8_t>(1));
			Write(current.guestThread + 0x54, m_currentIrql);
		}
		m_objectChanged.notify_all();
		WakeThreads();
		if (ordinal == 146 && selectedThread) {
			object->manualReset = originalManualReset; object->signaled = false; SyncDispatcherSignal(object);
		}
		SyncReadyList();
		m_regs->eax = b; FinishStdcall(ordinal == 145 ? 3 : 2); break;
	}
	case 148: { // KeSetPriorityThread
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal);
		auto* thread = FindThreadByGuestAddress(a);
		if (!thread) { m_regs->eax = 0; FinishStdcall(2); break; }
		thread->priority = static_cast<std::int8_t>(b);
		thread->basePriority = thread->priority;
		Write(thread->guestThread + 0x32, thread->priority);
		Write(thread->guestThread + 0x70, thread->basePriority);
		m_regs->eax = 1;
		FinishStdcall(2); break;
	}
	case 147: // KeSetPriorityProcess
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a + 0x18, 1)) return Unsupported(ordinal);
		{
			std::uint8_t old = 0; Read(a + 0x18, old);
			const std::int8_t priority = static_cast<std::int8_t>(b);
			Write(a + 0x18, priority);
			for (auto& thread : m_threads) {
				std::uint8_t priorityDecrement = 0;
				if (!Read(thread.guestThread + 0x72, priorityDecrement) || priorityDecrement != 0) continue;
				thread.basePriority = priority; thread.priority = priority;
				Write(thread.guestThread + 0x70, priority); Write(thread.guestThread + 0x32, priority);
			}
			m_regs->eax = static_cast<std::uint32_t>(static_cast<std::int32_t>(static_cast<std::int8_t>(old)));
		}
		FinishStdcall(2); break;
	case 155: // KeTestAlertThread
		if (!ReadStack(0, a) || a > 1) return Unsupported(ordinal); {
			auto& thread = m_threads[m_currentThreadIndex]; const bool pendingUserApc = a != 0 && std::any_of(thread.apcs.begin(), thread.apcs.end(), [](const ApcItem& item) { return item.userMode; });
			m_regs->eax = thread.alerted[a] || pendingUserApc; thread.alerted[a] = false; Write(thread.guestThread + 0x2D + a, static_cast<std::uint8_t>(0));
		} FinishStdcall(1); break;
	case 149: case 150: { // KeSetTimer / KeSetTimerEx (LARGE_INTEGER by value)
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c)) return Unsupported(ordinal);
		auto object = GetDispatcherObject(a); if (!object || object->kind != ObjectKind::Timer) return Unsupported(ordinal);
		std::uint32_t timerDpc = 0; ReadStack(ordinal == 149 ? 3 : 4, timerDpc);
		const std::int64_t due = static_cast<std::int64_t>((static_cast<std::uint64_t>(c) << 32) | b);
		std::uint64_t ticks = due < 0 ? static_cast<std::uint64_t>(-due) : 0;
		if (due > 0) { FILETIME nowFile = {}; GetSystemTimeAsFileTime(&nowFile); const std::uint64_t now = (static_cast<std::uint64_t>(nowFile.dwHighDateTime) << 32) | nowFile.dwLowDateTime; ticks = static_cast<std::uint64_t>(due) > now ? static_cast<std::uint64_t>(due) - now : 0; }
		{ std::lock_guard<std::mutex> lock(m_objectMutex); d = object->timerActive ? 1 : 0; object->timerActive = true; object->signaled = false; object->timerDpc = timerDpc;
			object->timerApcRoutine = object->timerApcContext = object->timerThreadId = 0;
			object->timerApcUserMode = false;
			Write(a + 3, static_cast<std::uint8_t>(1)); Write(a + 4, 0u);
			object->due = std::chrono::steady_clock::now() + std::chrono::nanoseconds(ticks * 100);
			if (ordinal == 150) { std::uint32_t period = 0; ReadStack(3, period); object->period = std::chrono::milliseconds(period); } else object->period = {}; }
		m_objectChanged.notify_all(); m_regs->eax = d; FinishStdcall(ordinal == 149 ? 4 : 5); break;
	}
	case 38: // HalClearSoftwareInterrupt, fastcall
		a = m_regs->ecx; if (a < 32) m_softwareInterrupts &= ~(1u << a); FinishFastcall(); break;
	case 39: // HalDisableSystemInterrupt
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		if (a < 32) { std::lock_guard<std::mutex> lock(m_interruptMutex); m_enabledInterrupts &= ~(1u << a); m_pendingInterrupts.erase(std::remove(m_pendingInterrupts.begin(), m_pendingInterrupts.end(), a), m_pendingInterrupts.end()); }
		FinishStdcall(1); break;
	case 43: // HalEnableSystemInterrupt
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal);
		if (a < 32) { std::lock_guard<std::mutex> lock(m_interruptMutex); m_enabledInterrupts |= 1u << a; auto found = m_interrupts.find(a); if (found != m_interrupts.end()) { found->second.mode = b; if (!found->second.inService && (found->second.pulsePending || found->second.assertedSources) && std::find(m_pendingInterrupts.begin(), m_pendingInterrupts.end(), a) == m_pendingInterrupts.end()) m_pendingInterrupts.push_back(a); } }
		FinishStdcall(2); break;
	case 44: // HalGetInterruptVector
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal);
		if (a <= 27) { if (b) Write(b, static_cast<std::uint8_t>(27u - a)); m_regs->eax = a + 0x30; }
		else m_regs->eax = 0; FinishStdcall(2); break;
	case 45: { // HalReadSMBusValue
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !ReadStack(3, d) || !IsRangeValid(d, 4)) return Unsupported(ordinal);
		std::uint32_t value = 0; const bool ok = CxbxUwpReadSmbusValue(static_cast<std::uint8_t>(a), static_cast<std::uint8_t>(b), c != 0, value);
		if (ok) Write(d, value); m_regs->eax = ok ? StatusSuccess : StatusInvalidDeviceRequest; FinishStdcall(4); break;
	}
	case 46: { // HalReadWritePCISpace
		std::uint32_t reg = 0, buffer = 0, length = 0, write = 0;
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, reg) || !ReadStack(3, buffer) || !ReadStack(4, length) || !ReadStack(5, write) || !IsRangeValid(buffer, length)) return Unsupported(ordinal);
		if (firstOrdinal && m_logger) {
			char line[224] = {};
			sprintf_s(line, "[uwp-kernel:pci] bus=%u slot=0x%08X reg=0x%X buffer=0x%08X length=%u write=%u.\r\n",
				a, b, reg, buffer, length, write ? 1u : 0u);
			m_logger(line);
		}
		// PCI type-1 configuration space is 256 bytes. Do not let malformed
		// firmware arguments turn this synchronous HAL call into a multi-megabyte
		// loop, and use the same transfer-size table as the legacy Xbox HAL.
		if (reg >= 0x100u || length > 0x100u - reg) {
			if (!write && length) FillGuestMemory(buffer, 0xFF, (std::min)(length, 0x100u));
			FinishStdcall(6);
			break;
		}
		static constexpr std::uint8_t widths[4][4] = {
			{ 4, 1, 2, 2 }, { 1, 1, 1, 1 }, { 2, 1, 2, 2 }, { 1, 1, 1, 1 }
		};
		std::uint32_t lastValue = 0;
		for (std::uint32_t i = 0; i < length; ) {
			const std::uint32_t currentReg = reg + i;
			const std::uint32_t width = widths[currentReg & 3u][(length - i) & 3u];
			std::uint32_t value = 0;
			if (write) {
				if (width == 1) { std::uint8_t v = 0; Read(buffer + i, v); value = v; }
				else if (width == 2) { std::uint16_t v = 0; Read(buffer + i, v); value = v; }
				else Read(buffer + i, value);
				CxbxUwpWritePciConfig(a, b, currentReg, value, width);
			} else {
				value = CxbxUwpReadPciConfig(a, b, currentReg, width);
				if (width == 1) Write(buffer + i, static_cast<std::uint8_t>(value));
				else if (width == 2) Write(buffer + i, static_cast<std::uint16_t>(value));
				else Write(buffer + i, value);
			}
			lastValue = value;
			i += width;
		}
		if (firstOrdinal && m_logger) {
			char line[176] = {};
			sprintf_s(line, "[uwp-kernel:pci] transferencia concluida reg=0x%X valor=0x%08X write=%u.\r\n",
				reg, lastValue, write ? 1u : 0u);
			m_logger(line);
		}
		FinishStdcall(6); break;
	}
	case 47: { // HalRegisterShutdownNotification
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 16)) return Unsupported(ordinal);
		auto found = std::find(m_shutdownRegistrations.begin(), m_shutdownRegistrations.end(), a);
		if (b) {
			if (found == m_shutdownRegistrations.end()) m_shutdownRegistrations.push_back(a);
			std::stable_sort(m_shutdownRegistrations.begin(), m_shutdownRegistrations.end(),
				[this](std::uint32_t left, std::uint32_t right) {
					std::int32_t leftPriority = 0, rightPriority = 0;
					Read(left + 4, leftPriority); Read(right + 4, rightPriority);
					return leftPriority > rightPriority;
				});
		} else if (found != m_shutdownRegistrations.end()) {
			m_shutdownRegistrations.erase(found);
		}
		FinishStdcall(2); break;
	}
	case 48: // HalRequestSoftwareInterrupt, fastcall
		a = m_regs->ecx; if (a < 32) m_softwareInterrupts |= 1u << a;
		FinishFastcall();
		if (a == 2) DeliverPendingDpc();
		else if (a == 1 && !m_threads.empty()) DeliverPendingApc(m_threads[m_currentThreadIndex]);
		break;
	case 49: // HalReturnToFirmware
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		if (a == 1 || a == 2) {
			std::uint32_t launchPage = 0;
			if (Read(DataAddress(164), launchPage) && IsRangeValid(launchPage, 4096)) {
				std::memcpy(m_rebootLaunchData.data(), GuestPointer(launchPage, m_rebootLaunchData.size()), m_rebootLaunchData.size());
				std::string xboxPath;
				for (std::size_t index = 0; index < 520; ++index) {
					std::uint8_t byte = 0; if (!Read(launchPage + 8 + static_cast<std::uint32_t>(index), byte)) break;
					const char character = static_cast<char>(byte);
					if (!character) break;
					xboxPath.push_back(character == ';' ? '\\' : character);
				}
				while (!xboxPath.empty() && (xboxPath.front() == ';' || xboxPath.front() == ' '))
					xboxPath.erase(xboxPath.begin());
				std::string relative = xboxPath;
				auto stripPrefix = [&relative](const char* prefix) {
					const std::size_t length = std::strlen(prefix);
					if (relative.size() < length || _strnicmp(relative.c_str(), prefix, length) != 0) return false;
					relative.erase(0, length); while (!relative.empty() && (relative.front() == '\\' || relative.front() == '/')) relative.erase(relative.begin()); return true;
				};
				stripPrefix("\\Device\\CdRom0"); stripPrefix("D:");
				std::replace(relative.begin(), relative.end(), '/', '\\');
				const bool safe = !relative.empty() && relative.find("..") == std::string::npos &&
					relative.find_first_of("<>|\"?*") == std::string::npos;
				if (safe) {
					m_rebootRequested = true;
					if (m_xiso) {
						m_rebootHostPath = m_gamePath;
						m_rebootXisoEntry = relative;
					} else {
						m_rebootHostPath = m_gameRoot;
						if (!m_rebootHostPath.empty() && m_rebootHostPath.back() != L'\\') m_rebootHostPath.push_back(L'\\');
						for (const char character : relative) m_rebootHostPath.push_back(static_cast<unsigned char>(character));
						m_rebootXisoEntry.clear();
					}
				}
			}
		}
		if (m_logger) {
			std::uint32_t caller = 0; Read(m_regs->esp, caller);
			char line[256] = {};
			sprintf_s(line, "[uwp-kernel:shutdown] HalReturnToFirmware rotina=%u caller=0x%08X reboot=%u.\r\n",
				a, caller, m_rebootRequested ? 1u : 0u);
			m_logger(line);
		}
		m_shutdownPending = true; FinishStdcall(1);
		if (!StartShutdownNotifications(true)) TerminateCurrentThread(StatusSuccess); break;
	case 50: // HalWriteSMBusValue
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !ReadStack(3, d)) return Unsupported(ordinal);
		m_regs->eax = CxbxUwpWriteSmbusValue(static_cast<std::uint8_t>(a), static_cast<std::uint8_t>(b), c != 0, d) ? StatusSuccess : StatusInvalidDeviceRequest; FinishStdcall(4); break;
	case 56: { // InterlockedFlushSList, fastcall
		a = m_regs->ecx; if (!IsRangeValid(a, 8)) return Unsupported(ordinal); std::uint32_t head = 0; Read(a, head); Write(a, 0u); Write(a + 4, 0u); m_regs->eax = head; FinishFastcall(); break;
	}
	case 57: { // InterlockedPopEntrySList, fastcall
		a = m_regs->ecx; if (!IsRangeValid(a, 8)) return Unsupported(ordinal); std::uint32_t head = 0, next = 0; std::uint16_t depth = 0, sequence = 0; Read(a, head); Read(a + 4, depth); Read(a + 6, sequence);
		if (head) { if (!Read(head, next)) return Unsupported(ordinal); Write(a, next); if (depth) --depth; ++sequence; Write(a + 4, depth); Write(a + 6, sequence); } m_regs->eax = head; FinishFastcall(); break;
	}
	case 58: { // InterlockedPushEntrySList, fastcall
		a = m_regs->ecx; b = m_regs->edx; if (!IsRangeValid(a, 8) || !IsRangeValid(b, 4)) return Unsupported(ordinal); std::uint32_t head = 0; std::uint16_t depth = 0, sequence = 0; Read(a, head); Read(a + 4, depth); Read(a + 6, sequence);
		Write(b, head); Write(a, b); ++depth; ++sequence; Write(a + 4, depth); Write(a + 6, sequence); m_regs->eax = head; FinishFastcall(); break;
	}
	case 59: { // IoAllocateIrp
		if (!ReadStack(0, a)) return Unsupported(ordinal); if (!a || a > 64) { m_regs->eax = 0; FinishStdcall(1); break; }
		const std::uint32_t size = 0x60 + a * 0x18; const std::uint32_t irp = Allocate(size);
		if (irp) { FillGuestMemory(irp, 0, size); Write(irp, static_cast<std::int16_t>(6)); Write(irp + 2, static_cast<std::uint16_t>(size)); Write(irp + 0x18, static_cast<std::uint8_t>(a)); Write(irp + 0x19, static_cast<std::uint8_t>(a + 1)); Write(irp + 0x58, irp + size); }
		m_regs->eax = irp; FinishStdcall(1); break;
	}
	case 60: case 62: { // IoBuildAsynchronous/SynchronousFsdRequest
		std::uint32_t device = 0, buffer = 0, length = 0, offset = 0, event = 0, iosb = 0;
		if (!ReadStack(0, a) || !ReadStack(1, device) || !ReadStack(2, buffer) ||
			!ReadStack(3, length) || !ReadStack(4, offset) ||
			(ordinal == 60 && !ReadStack(5, iosb)) ||
			(ordinal == 62 && (!ReadStack(5, event) || !ReadStack(6, iosb))))
			return Unsupported(ordinal);
		const bool valid = (a == 3 || a == 4 || a == 6) && IsRangeValid(device, 0x20) &&
			(!length || IsRangeValid(buffer, length)) && (!offset || IsRangeValid(offset, 8)) &&
			(!iosb || IsRangeValid(iosb, 8)) && (ordinal == 60 ||
			(event && iosb && IsRangeValid(event, 16) && GetDispatcherObject(event)));
		if (!valid) { m_regs->eax = 0; FinishStdcall(ordinal == 60 ? 6 : 7); break; }
		std::uint8_t stackSize = 1;
		Read(device + 0x1E, stackSize); stackSize = (std::max<std::uint8_t>)(stackSize, 1);
		const std::uint32_t irpSize = 0x60 + stackSize * 0x18, irp = Allocate(irpSize);
		if (irp) {
			FillGuestMemory(irp, 0, irpSize);
			Write(irp, static_cast<std::int16_t>(6)); Write(irp + 2, static_cast<std::uint16_t>(irpSize));
			Write(irp + 0x18, stackSize); Write(irp + 0x19, static_cast<std::uint8_t>(stackSize + 1));
			Write(irp + 0x1C, iosb); Write(irp + 0x20, event); Write(irp + 0x30, buffer);
			const std::uint32_t stack = irp + 0x60 + (stackSize - 1) * 0x18;
			Write(stack, static_cast<std::uint8_t>(a)); Write(stack + 4, length);
			if (offset) { std::uint64_t position = 0; Read(offset, position); Write(stack + 0x0C, position); }
			Write(irp + 0x58, irp + irpSize);
		}
		m_regs->eax = irp; FinishStdcall(ordinal == 60 ? 6 : 7); break;
	}
	case 61: { // IoBuildDeviceIoControlRequest
		std::uint32_t device = 0, input = 0, inputLength = 0, output = 0, outputLength = 0;
		std::uint32_t internal = 0, event = 0, iosb = 0;
		if (!ReadStack(0, a) || !ReadStack(1, device) || !ReadStack(2, input) ||
			!ReadStack(3, inputLength) || !ReadStack(4, output) || !ReadStack(5, outputLength) ||
			!ReadStack(6, internal) || !ReadStack(7, event) || !ReadStack(8, iosb)) return Unsupported(ordinal);
		if (!IsRangeValid(device, 0x20) || (inputLength && !IsRangeValid(input, inputLength)) ||
			(outputLength && !IsRangeValid(output, outputLength)) || !event || !iosb ||
			!IsRangeValid(event, 16) || !GetDispatcherObject(event) || !IsRangeValid(iosb, 8)) {
			m_regs->eax = 0; FinishStdcall(9); break;
		}
		std::uint8_t stackSize = 1; Read(device + 0x1E, stackSize);
		stackSize = (std::max<std::uint8_t>)(stackSize, 1);
		const std::uint32_t size = 0x60 + stackSize * 0x18, irp = Allocate(size);
		if (irp) {
			FillGuestMemory(irp, 0, size); Write(irp, static_cast<std::int16_t>(6));
			Write(irp + 2, static_cast<std::uint16_t>(size)); Write(irp + 0x18, stackSize);
			Write(irp + 0x19, static_cast<std::uint8_t>(stackSize + 1)); Write(irp + 0x1C, iosb);
			Write(irp + 0x20, event); Write(irp + 0x30, output); Write(irp + 0x28, input);
			const std::uint32_t stack = irp + 0x60 + (stackSize - 1) * 0x18;
			Write(stack, static_cast<std::uint8_t>(internal ? 11 : 10)); Write(stack + 4, outputLength);
			Write(stack + 8, inputLength); Write(stack + 0x0C, a); Write(stack + 0x10, input);
			Write(irp + 0x58, irp + size);
		}
		m_regs->eax = irp; FinishStdcall(9); break;
	}
	case 63: { // IoCheckShareAccess
		std::uint32_t share = 0, file = 0, accessState = 0, update = 0; if (!ReadStack(0, a) || !ReadStack(1, share) || !ReadStack(2, file) || !ReadStack(3, accessState) || !ReadStack(4, update) || !IsRangeValid(file, 3) || !IsRangeValid(accessState, 7)) return Unsupported(ordinal); const bool read = (a & 0x21) != 0, write = (a & 0x6) != 0, del = (a & 0x10000) != 0, sr = (share & 1) != 0, sw = (share & 2) != 0, sd = (share & 4) != 0; std::uint8_t values[7] = {}; for (int i = 0; i < 7; ++i) Read(accessState + i, values[i]); const bool violation = (read && values[4] < values[0]) || (write && values[5] < values[0]) || (del && values[6] < values[0]) || (values[1] && !sr) || (values[2] && !sw) || (values[3] && !sd); if (violation) m_regs->eax = 0xC0000043u; else { std::uint8_t flags = static_cast<std::uint8_t>((read ? 2 : 0) | (write ? 4 : 0) | (del ? 8 : 0) | (sr ? 16 : 0) | (sw ? 32 : 0) | (sd ? 64 : 0)); Write(file + 2, flags); if (update) { ++values[0]; values[1] += read; values[2] += write; values[3] += del; values[4] += sr; values[5] += sw; values[6] += sd; for (int i = 0; i < 7; ++i) Write(accessState + i, values[i]); } m_regs->eax = StatusSuccess; } FinishStdcall(5); break;
	}
	case 65: { // IoCreateDevice
		std::uint32_t extensionSize = 0, nameDesc = 0, deviceType = 0, exclusive = 0, out = 0;
		if (!ReadStack(0, a) || !ReadStack(1, extensionSize) || !ReadStack(2, nameDesc) ||
			!ReadStack(3, deviceType) || !ReadStack(4, exclusive) || !ReadStack(5, out) ||
			!IsRangeValid(out, 4) || (nameDesc && !IsRangeValid(nameDesc, 8))) return Unsupported(ordinal);
		Write(out, 0u);
		const std::uint64_t requestedSize = 0x4Cull + extensionSize;
		if (requestedSize > std::numeric_limits<std::uint16_t>::max()) { m_regs->eax = StatusInvalidParameter; FinishStdcall(6); break; }
		const std::uint32_t totalSize = static_cast<std::uint32_t>((requestedSize + 7) & ~7ull);
		std::wstring name;
		if (nameDesc) {
			std::uint16_t length = 0, maximum = 0; std::uint32_t buffer = 0;
			Read(nameDesc, length); Read(nameDesc + 2, maximum); Read(nameDesc + 4, buffer);
			if (length > maximum || (length && !IsRangeValid(buffer, length))) { m_regs->eax = StatusInvalidParameter; FinishStdcall(6); break; }
			for (std::uint32_t i = 0; i < length; ++i) { std::uint8_t character = 0; Read(buffer + i, character); name.push_back(static_cast<wchar_t>(character)); }
			if (!name.empty() && m_namedObjects.count(NormalizeObjectName(name))) { m_regs->eax = 0xC0000035u; FinishStdcall(6); break; }
		}
		auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::Directory;
		object->objectType = DataAddress(70); object->guestBodySize = totalSize;
		object->path = name; object->permanent = !name.empty(); object->attached = !name.empty();
		object->references = name.empty() ? 1u : 2u;
		if (!EnsureGuestObjectBody(object)) m_regs->eax = StatusNoMemory;
		else {
			const std::uint32_t device = object->guestAddress;
			FillGuestMemory(device, 0, totalSize);
			Write(device, static_cast<std::int16_t>(3)); Write(device + 2, static_cast<std::uint16_t>(requestedSize));
			Write(device + 4, 0u); Write(device + 8, a);
			const bool removableType = deviceType == 2 || deviceType == 7 || deviceType == 0x3A || deviceType == 0x3B;
			Write(device + 0x0C, removableType ? 0u : device);
			Write(device + 0x14, 0x10u | (exclusive ? 2u : 0u) | (!name.empty() ? 8u : 0u));
			Write(device + 0x18, extensionSize ? device + 0x4C : 0u);
			if (extensionSize >= 4) Write(device + 0x4C, device);
			Write(device + 0x1C, static_cast<std::uint8_t>(deviceType)); Write(device + 0x1E, static_cast<std::int8_t>(1));
			Write(device + 0x20, 512u); Write(device + 0x28, static_cast<std::int16_t>(0x14));
			Write(device + 0x2A, static_cast<std::uint8_t>(12)); Write(device + 0x2B, static_cast<std::uint8_t>(0));
			Write(device + 0x2C, device + 0x2C); Write(device + 0x30, device + 0x2C);
			InitializeDispatcher(device + 0x34, 1, 1);
			if (!name.empty()) {
				std::uint32_t flags = 0; Read(object->allocationBase + 12, flags); Write(object->allocationBase + 12, flags | 4u);
				m_namedObjects[NormalizeObjectName(name)] = object;
			}
			Write(out, device); m_regs->eax = StatusSuccess;
		}
		FinishStdcall(6); break;
	}
	case 66: { // IoCreateFile
		std::uint32_t access = 0, attrs = 0, iosb = 0, share = 0, disposition = 0, options = 0, ioOptions = 0;
		if (!ReadStack(0, a) || !ReadStack(1, access) || !ReadStack(2, attrs) || !ReadStack(3, iosb) ||
			!ReadStack(6, share) || !ReadStack(7, disposition) || !ReadStack(8, options) || !ReadStack(9, ioOptions)) return Unsupported(ordinal);
		(void)ioOptions;
		m_regs->eax = OpenGuestFile(a, access, attrs, iosb, share, disposition, options); FinishStdcall(10); break;
	}
	case 67: { // IoCreateSymbolicLink
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 8) || !IsRangeValid(b, 8)) return Unsupported(ordinal);
		auto readName = [this](std::uint32_t desc, std::wstring& value) {
			std::uint16_t length = 0, maximum = 0; std::uint32_t buffer = 0;
			if (!Read(desc, length) || !Read(desc + 2, maximum) || !Read(desc + 4, buffer) ||
				length > maximum || (length && !IsRangeValid(buffer, length))) return false;
			for (std::uint32_t i = 0; i < length; ++i) { std::uint8_t character = 0; Read(buffer + i, character); value.push_back(static_cast<wchar_t>(character)); }
			return true;
		};
		std::wstring name, target;
		if (!readName(a, name) || !readName(b, target) || name.empty() || target.empty() ||
			name.front() != L'\\' || target.front() != L'\\') m_regs->eax = StatusInvalidParameter;
		else if (m_namedObjects.count(NormalizeObjectName(name))) m_regs->eax = 0xC0000035u;
		else {
			auto targetEntry = m_namedObjects.find(NormalizeObjectName(target));
			if (targetEntry == m_namedObjects.end()) { m_regs->eax = StatusInvalidParameter; FinishStdcall(2); break; }
			auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::SymbolicLink;
			object->objectType = DataAddress(249); object->path = name; object->target = target;
			object->linkTarget = targetEntry->second; object->guestBodySize = 12u + static_cast<std::uint32_t>(target.size()) + 1u;
			object->permanent = true; object->attached = true; object->references = 1;
			if (EnsureGuestObjectBody(object)) {
				const std::uint32_t buffer = object->guestAddress + 12;
				Write(object->guestAddress, object->linkTarget->guestAddress);
				Write(object->guestAddress + 4, static_cast<std::uint16_t>(target.size()));
				Write(object->guestAddress + 6, static_cast<std::uint16_t>(target.size() + 1));
				Write(object->guestAddress + 8, buffer);
				if (auto* output = GuestPointer(buffer, target.size() + 1)) {
					for (std::size_t i = 0; i < target.size(); ++i) output[i] = static_cast<std::uint8_t>(target[i]);
					output[target.size()] = 0;
				}
				std::uint32_t flags = 0; Read(object->allocationBase + 12, flags); Write(object->allocationBase + 12, flags | 6u);
				++object->linkTarget->references;
				if (object->linkTarget->allocationBase) Write(object->linkTarget->allocationBase, object->linkTarget->references);
				m_namedObjects[NormalizeObjectName(name)] = object; m_regs->eax = StatusSuccess;
			} else m_regs->eax = StatusNoMemory;
		}
		FinishStdcall(2); break;
	}
	case 68: // IoDeleteDevice
		if (!ReadStack(0, a) || !IsRangeValid(a, 0x4C)) return Unsupported(ordinal); {
			Write(a + 0x1F, static_cast<std::uint8_t>(1));
			std::uint32_t deviceReferences = 0; Read(a + 4, deviceReferences);
			if (!deviceReferences) {
				auto found = m_guestObjects.find(a);
				if (found != m_guestObjects.end()) {
					auto object = found->second;
					object->permanent = false;
					if (object->attached) {
						if (!object->path.empty()) m_namedObjects.erase(NormalizeObjectName(object->path));
						object->attached = false;
						if (object->allocationBase) { std::uint32_t flags = 0; Read(object->allocationBase + 12, flags); Write(object->allocationBase + 12, flags & ~6u); }
						DereferenceObject(object, true);
					}
					DereferenceObject(object, true);
				}
			}
		} FinishStdcall(1); break;
	case 69: // IoDeleteSymbolicLink
		if (!ReadStack(0, a) || !IsRangeValid(a, 8)) return Unsupported(ordinal); {
			std::uint16_t length = 0, maximum = 0; std::uint32_t buffer = 0;
			Read(a, length); Read(a + 2, maximum); Read(a + 4, buffer);
			if (length > maximum || (length && !IsRangeValid(buffer, length))) m_regs->eax = StatusInvalidParameter;
			else { std::wstring name; for (std::uint32_t i = 0; i < length; ++i) { std::uint8_t character = 0; Read(buffer + i, character); name.push_back(static_cast<wchar_t>(character)); }
				auto found = m_namedObjects.find(NormalizeObjectName(name));
				if (found == m_namedObjects.end() || found->second->kind != ObjectKind::SymbolicLink) m_regs->eax = StatusObjectNameNotFound;
				else { auto object = found->second; object->permanent = false; object->attached = false; m_namedObjects.erase(found); if (object->allocationBase) { std::uint32_t flags = 0; Read(object->allocationBase + 12, flags); Write(object->allocationBase + 12, flags & ~6u); } DereferenceObject(object, true); m_regs->eax = StatusSuccess; }
			}
		} FinishStdcall(1); break;
	case 72: // IoFreeIrp
		if (!ReadStack(0, a)) return Unsupported(ordinal); Free(a); FinishStdcall(1); break;
	case 73: { // IoInitializeIrp
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !c || c > 64 ||
			b < 0x60 + c * 0x18 || !IsRangeValid(a, b)) return Unsupported(ordinal);
		FillGuestMemory(a, 0, b); Write(a, static_cast<std::int16_t>(6));
		Write(a + 2, static_cast<std::uint16_t>(b)); Write(a + 0x18, static_cast<std::int8_t>(c));
		Write(a + 0x19, static_cast<std::int8_t>(c + 1)); Write(a + 0x58, a + b);
		m_regs->eax = a; FinishStdcall(3); break;
	}
	case 74: // IoInvalidDeviceRequest
		if (!ReadStack(1, a) || !IsRangeValid(a, 0x60)) return Unsupported(ordinal); Write(a + 0x10, StatusInvalidDeviceRequest); CompleteIrp(a); m_regs->eax = StatusInvalidDeviceRequest; FinishStdcall(2); break;
	case 75: { // IoQueryFileInformation
		std::uint32_t infoClass = 0, length = 0, info = 0, returned = 0; if (!ReadStack(0, a) || !ReadStack(1, infoClass) || !ReadStack(2, length) || !ReadStack(3, info) || !ReadStack(4, returned)) return Unsupported(ordinal); std::uint32_t used = 0, status = StatusSuccess; if (infoClass == 14 && length >= 8 && IsRangeValid(info, 8) && IsRangeValid(a + 0x14, 8)) { std::uint64_t offset = 0; Read(a + 0x14, offset); Write(info, offset); used = 8; } else if (infoClass == 5 && length >= 24 && FillGuestMemory(info, 0, 24)) { used = 24; } else status = StatusBufferTooSmall; if (returned) Write(returned, used); m_regs->eax = status; FinishStdcall(5); break;
	}
	case 76: { // IoQueryVolumeInformation
		std::uint32_t infoClass = 0, length = 0, info = 0, returned = 0; if (!ReadStack(0, a) || !ReadStack(1, infoClass) || !ReadStack(2, length) || !ReadStack(3, info) || !ReadStack(4, returned)) return Unsupported(ordinal); std::uint32_t used = 0, status = StatusSuccess; if (infoClass == 3 && length >= 24 && IsRangeValid(info, 24)) { Write(info, 0x01000000ull); Write(info + 8, 0x00800000ull); Write(info + 16, 8u); Write(info + 20, 512u); used = 24; } else if (infoClass == 4 && length >= 8 && IsRangeValid(info, 8)) { Write(info, 7u); Write(info + 4, 0u); used = 8; } else status = StatusBufferTooSmall; if (returned) Write(returned, used); m_regs->eax = status; FinishStdcall(5); break;
	}
	case 77: // IoQueueThreadIrp
		if (!ReadStack(0, a) || !IsRangeValid(a, 0x60)) return Unsupported(ordinal); {
			const std::uint32_t head = m_currentThread + 0x134; std::uint32_t tail = head; Read(head + 4, tail); if (!IsRangeValid(tail, 8)) tail = head;
			Write(a + 0x50, head); Write(a + 0x54, tail); Write(tail, a + 0x50); Write(head + 4, a + 0x50); Write(a + 0x4C, m_currentThread);
		} FinishStdcall(1); break;
	case 78: { // IoRemoveShareAccess
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a + 2, 1) || !IsRangeValid(b, 7)) return Unsupported(ordinal); std::uint8_t flags = 0, values[7] = {}; Read(a + 2, flags); for (int i = 0; i < 7; ++i) Read(b + i, values[i]); if (values[0]) --values[0]; if ((flags & 2) && values[1]) --values[1]; if ((flags & 4) && values[2]) --values[2]; if ((flags & 8) && values[3]) --values[3]; if ((flags & 16) && values[4]) --values[4]; if ((flags & 32) && values[5]) --values[5]; if ((flags & 64) && values[6]) --values[6]; for (int i = 0; i < 7; ++i) Write(b + i, values[i]); FinishStdcall(2); break;
	}
	case 79: { // IoSetIoCompletion
		std::uint32_t key = 0, apc = 0, status = 0, information = 0; if (!ReadStack(0, a) || !ReadStack(1, key) || !ReadStack(2, apc) || !ReadStack(3, status) || !ReadStack(4, information)) return Unsupported(ordinal); ObjectPtr object; auto found = m_guestObjects.find(a); if (found != m_guestObjects.end()) object = found->second; if (!object) { object = std::make_shared<KernelObject>(); object->kind = ObjectKind::IoCompletion; object->guestAddress = a; object->manualReset = true; m_guestObjects[a] = object; m_dispatcherObjects[a] = object; } object->completions.push_back({ key, apc, status, information }); object->signaled = true; SyncDispatcherSignal(object); m_objectChanged.notify_all(); m_regs->eax = StatusSuccess; FinishStdcall(5); WakeThreads(); SyncReadyList(); break;
	}
	case 80: { // IoSetShareAccess
		std::uint32_t share = 0, file = 0, accessState = 0; if (!ReadStack(0, a) || !ReadStack(1, share) || !ReadStack(2, file) || !ReadStack(3, accessState) || !IsRangeValid(file + 2, 1) || !IsRangeValid(accessState, 7)) return Unsupported(ordinal); const bool read = (a & 0x21) != 0, write = (a & 0x6) != 0, del = (a & 0x10000) != 0, sr = (share & 1) != 0, sw = (share & 2) != 0, sd = (share & 4) != 0; Write(file + 2, static_cast<std::uint8_t>((read ? 2 : 0) | (write ? 4 : 0) | (del ? 8 : 0) | (sr ? 16 : 0) | (sw ? 32 : 0) | (sd ? 64 : 0))); const std::uint8_t values[7] = { 1, static_cast<std::uint8_t>(read), static_cast<std::uint8_t>(write), static_cast<std::uint8_t>(del), static_cast<std::uint8_t>(sr), static_cast<std::uint8_t>(sw), static_cast<std::uint8_t>(sd) }; for (int i = 0; i < 7; ++i) Write(accessState + i, values[i]); FinishStdcall(4); break;
	}
	case 81: case 82: { // IoStartNextPacket[/ByKey]
		std::uint32_t key = 0;
		if (!ReadStack(0, a) || (ordinal == 82 && !ReadStack(1, key)) || !IsRangeValid(a, 0x4C)) return Unsupported(ordinal);
		std::uint32_t head = 0; Read(a + 0x2C, head);
		if (head == a + 0x2C) { Write(a + 0x10, 0u); Write(a + 0x2B, static_cast<std::uint8_t>(0)); FinishStdcall(ordinal == 81 ? 1 : 2); break; }
		std::uint32_t selected = head;
		if (ordinal == 82) {
			for (std::uint32_t cursor = head; cursor != a + 0x2C;) {
				std::uint32_t sortKey = 0, next = a + 0x2C; Read(cursor + 8, sortKey);
				if (key <= sortKey) { selected = cursor; break; }
				Read(cursor, next); cursor = next;
			}
		}
		std::uint32_t next = 0, previous = 0; Read(selected, next); Read(selected + 4, previous);
		Write(previous, next); Write(next + 4, previous); Write(selected + 12, static_cast<std::uint8_t>(0));
		const std::uint32_t irp = selected - 0x3C; Write(a + 0x10, irp);
		std::uint32_t driver = 0, start = 0; Read(a + 8, driver); if (driver) Read(driver, start);
		FinishStdcall(ordinal == 81 ? 1 : 2);
		if (start && IsRangeValid(start, 1)) { m_driverFrames.push_back({ *m_regs, irp, 0, nullptr, false, false }); m_regs->esp -= 4; Write(m_regs->esp, irp); m_regs->esp -= 4; Write(m_regs->esp, a); m_regs->esp -= 4; Write(m_regs->esp, StubBase + DriverReturnOrdinal * StubStride); m_regs->eip = start; } break;
	}
	case 83: { // IoStartPacket
		std::uint32_t irp = 0, keyPtr = 0; if (!ReadStack(0, a) || !ReadStack(1, irp) || !ReadStack(2, keyPtr) || !IsRangeValid(a, 0x4C) || !IsRangeValid(irp, 0x60) || (keyPtr && !IsRangeValid(keyPtr, 4))) return Unsupported(ordinal); std::uint8_t busy = 0; Read(a + 0x2B, busy); if (busy) { const std::uint32_t entry = irp + 0x3C; std::uint32_t before = a + 0x2C, key = 0; if (keyPtr) { Read(keyPtr, key); Read(a + 0x2C, before); while (before != a + 0x2C) { std::uint32_t queuedKey = 0, next = 0; Read(before + 8, queuedKey); if (key < queuedKey) break; Read(before, next); before = next; } } std::uint32_t previous = 0; Read(before + 4, previous); Write(entry, before); Write(entry + 4, previous); Write(previous, entry); Write(before + 4, entry); Write(entry + 8, key); Write(entry + 12, static_cast<std::uint8_t>(1)); FinishStdcall(3); } else { Write(a + 0x2B, static_cast<std::uint8_t>(1)); Write(a + 0x10, irp); if (keyPtr) { Read(keyPtr, b); Write(a + 0x48, b); } std::uint32_t driver = 0, start = 0; Read(a + 8, driver); if (driver) Read(driver, start); FinishStdcall(3); if (start && IsRangeValid(start, 1)) { m_driverFrames.push_back({ *m_regs, irp, 0, nullptr, false, false }); m_regs->esp -= 4; Write(m_regs->esp, irp); m_regs->esp -= 4; Write(m_regs->esp, a); m_regs->esp -= 4; Write(m_regs->esp, StubBase + DriverReturnOrdinal * StubStride); m_regs->eip = start; } } break;
	}
	case 84: case 85: { // IoSynchronousDeviceIoControlRequest / IoSynchronousFsdRequest
		std::uint32_t device = 0, buffer = 0, length = 0, output = 0, outputLength = 0, returned = 0, internal = 0, offset = 0;
		if (!ReadStack(0, a) || !ReadStack(1, device) || !ReadStack(2, buffer) || !ReadStack(3, length) || !IsRangeValid(device, 0x20)) return Unsupported(ordinal);
		if (m_dismountedDevices.count(device)) { m_regs->eax = 0xC000026Eu; FinishStdcall(ordinal == 84 ? 8 : 5); break; }
		if (ordinal == 84) { if (!ReadStack(4, output) || !ReadStack(5, outputLength) || !ReadStack(6, returned) || !ReadStack(7, internal)) return Unsupported(ordinal); }
		else if (!ReadStack(4, offset)) return Unsupported(ordinal);
		std::uint8_t stackCount = 1; Read(device + 0x1E, stackCount); stackCount = (std::max<std::uint8_t>)(stackCount, 1);
		const std::uint32_t size = 0x60 + stackCount * 0x18, irp = Allocate(size);
		if (!irp) { m_regs->eax = 0xC0000017u; FinishStdcall(ordinal == 84 ? 8 : 5); break; }
		FillGuestMemory(irp, 0, size); Write(irp, static_cast<std::int16_t>(6)); Write(irp + 2, static_cast<std::uint16_t>(size)); Write(irp + 0x18, stackCount); Write(irp + 0x19, stackCount);
		const std::uint32_t stack = irp + 0x60 + (stackCount - 1) * 0x18; Write(irp + 0x58, stack);
		if (ordinal == 84) { Write(irp + 0x30, output); Write(irp + 0x28, static_cast<std::uint64_t>(buffer)); Write(stack, static_cast<std::uint8_t>(internal ? 11 : 10)); Write(stack + 4, outputLength); Write(stack + 8, length); Write(stack + 0x0C, a); Write(stack + 0x10, buffer); }
		else { Write(irp + 0x30, buffer); Write(stack, static_cast<std::uint8_t>(a)); Write(stack + 4, length); if (offset) { std::uint64_t value = 0; Read(offset, value); Write(stack + 0x0C, value); } }
		std::uint32_t driver = 0, dispatch = 0; std::uint8_t major = 0; Read(device + 8, driver); Read(stack, major); if (driver && major <= 13) Read(driver + 12 + major * 4, dispatch);
		FinishStdcall(ordinal == 84 ? 8 : 5);
		if (!dispatch || !IsRangeValid(dispatch, 1)) { Write(irp + 0x10, StatusInvalidDeviceRequest); if (returned) Write(returned, 0u); Free(irp); m_regs->eax = StatusInvalidDeviceRequest; break; }
		m_driverFrames.push_back({ *m_regs, irp, returned, nullptr, true, true });
		m_regs->esp -= 4; Write(m_regs->esp, irp); m_regs->esp -= 4; Write(m_regs->esp, device); m_regs->esp -= 4; Write(m_regs->esp, StubBase + DriverReturnOrdinal * StubStride); m_regs->eip = dispatch; break;
	}
	case 86: { // IofCallDriver, fastcall
		a = m_regs->ecx; b = m_regs->edx; if (!IsRangeValid(a, 0x20) || !IsRangeValid(b, 0x60)) return Unsupported(ordinal);
		if (m_dismountedDevices.count(a)) { Write(b + 0x10, 0xC000026Eu); m_regs->eax = 0xC000026Eu; FinishFastcall(); break; }
		std::uint8_t current = 0; std::uint32_t stack = 0; Read(b + 0x19, current); Read(b + 0x58, stack);
		std::uint8_t stackCount = 0; Read(b + 0x18, stackCount);
		if (!current || current > static_cast<std::uint8_t>(stackCount + 1) || stack < b + 0x60 || stack > b + 0x60 + stackCount * 0x18) { Write(b + 0x10, StatusInvalidParameter); m_regs->eax = StatusInvalidParameter; FinishFastcall(); break; }
		if (current > 1) { --current; stack -= 0x18; Write(b + 0x19, current); Write(b + 0x58, stack); }
		std::uint8_t major = 0; std::uint32_t driver = 0, dispatch = 0; Read(stack, major); Read(a + 8, driver); if (driver && major <= 13) Read(driver + 12 + major * 4, dispatch);
		FinishFastcall();
		if (!dispatch || !IsRangeValid(dispatch, 1)) { Write(b + 0x10, StatusInvalidDeviceRequest); m_regs->eax = StatusInvalidDeviceRequest; break; }
		m_driverFrames.push_back({ *m_regs, b, 0, nullptr, true, false });
		m_regs->esp -= 4; Write(m_regs->esp, b); m_regs->esp -= 4; Write(m_regs->esp, a); m_regs->esp -= 4; Write(m_regs->esp, StubBase + DriverReturnOrdinal * StubStride); m_regs->eip = dispatch; break;
	}
	case 87: { // IofCompleteRequest, fastcall
		a = m_regs->ecx; const std::int32_t priorityBoost = static_cast<std::int8_t>(m_regs->edx);
		if (!IsRangeValid(a, 0x60)) return Unsupported(ordinal);
		std::uint32_t ownerAddress = 0; Read(a + 0x4C, ownerAddress);
		CompleteIrp(a);
		if (priorityBoost > 0) if (auto* owner = FindThreadByGuestAddress(ownerAddress)) {
			owner->priority = (std::min<std::int32_t>)(31, owner->priority + priorityBoost);
			owner->quantumRemaining = owner->quantum;
			Write(owner->guestThread + 0x32, static_cast<std::uint8_t>(owner->priority));
		}
		FinishFastcall(); break;
	}
	case 90: // IoDismountVolume
		if (!ReadStack(0, a) || !IsRangeValid(a, 0x4C)) return Unsupported(ordinal); m_dismountedDevices.insert(a); Write(a + 0x10, 0u); Write(a + 0x2B, static_cast<std::uint8_t>(0)); m_regs->eax = StatusSuccess; FinishStdcall(1); break;
	case 91: { // IoDismountVolumeByName
		if (!ReadStack(0, a) || !IsRangeValid(a, 8)) return Unsupported(ordinal); std::uint16_t length = 0; std::uint32_t text = 0; Read(a, length); Read(a + 4, text); std::wstring name; for (std::uint32_t i = 0; i < length; ++i) { std::uint8_t character = 0; if (!Read(text + i, character)) break; name.push_back(static_cast<wchar_t>(character)); } auto found = m_namedObjects.find(NormalizeObjectName(name)); if (found == m_namedObjects.end() || !found->second->guestAddress) m_regs->eax = StatusObjectNameNotFound; else { m_dismountedDevices.insert(found->second->guestAddress); m_regs->eax = StatusSuccess; } FinishStdcall(1); break;
	}
	case 327: { // XeLoadSection
		if (!ReadStack(0, a) || !IsRangeValid(a, 56)) return Unsupported(ordinal); std::uint32_t address = 0, virtualSize = 0, fileOffset = 0, fileSize = 0, references = 0, head = 0, tail = 0; Read(a + 4, address); Read(a + 8, virtualSize); Read(a + 12, fileOffset); Read(a + 16, fileSize); Read(a + 24, references); Read(a + 28, head); Read(a + 32, tail);
		if (!IsRangeValid(address, virtualSize) || fileSize > virtualSize || m_gamePath.empty()) { m_regs->eax = StatusInvalidParameter; FinishStdcall(1); break; }
		if (!references) { CREATEFILE2_EXTENDED_PARAMETERS parameters = { sizeof(parameters) }; parameters.dwFileAttributes = FILE_ATTRIBUTE_NORMAL; HANDLE file = CreateFile2FromAppW(m_gamePath.c_str(), GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, &parameters); if (file == INVALID_HANDLE_VALUE) { m_regs->eax = StatusFromWin32(GetLastError()); FinishStdcall(1); break; } LARGE_INTEGER position = {}; position.QuadPart = m_gameImageOffset + fileOffset; bool ok = SetFilePointerEx(file, position, nullptr, FILE_BEGIN) != FALSE; auto* image = GuestPointer(address, virtualSize); std::memset(image, 0, virtualSize); std::uint32_t done = 0; while (ok && done < fileSize) { DWORD read = 0; const DWORD chunk = (std::min)(fileSize - done, 1u << 20); ok = ReadFile(file, image + done, chunk, &read, nullptr) != FALSE && read != 0; done += read; } CloseHandle(file); if (!ok || done != fileSize) { m_regs->eax = StatusEndOfFile; FinishStdcall(1); break; } std::uint16_t count = 0; if (head && Read(head, count)) Write(head, static_cast<std::uint16_t>(count + 1)); if (tail && Read(tail, count)) Write(tail, static_cast<std::uint16_t>(count + 1)); }
		Write(a + 24, references + 1); m_regs->eax = StatusSuccess; FinishStdcall(1); break;
	}
	case 328: { // XeUnloadSection
		if (!ReadStack(0, a) || !IsRangeValid(a, 56)) return Unsupported(ordinal); std::uint32_t references = 0, head = 0, tail = 0; Read(a + 24, references); Read(a + 28, head); Read(a + 32, tail); if (!references) m_regs->eax = StatusInvalidParameter; else { --references; Write(a + 24, references); if (!references) { std::uint16_t count = 0; if (head && Read(head, count) && count) Write(head, static_cast<std::uint16_t>(count - 1)); if (tail && Read(tail, count) && count) Write(tail, static_cast<std::uint16_t>(count - 1)); } m_regs->eax = StatusSuccess; } FinishStdcall(1); break;
	}
	case 329: case 330: case 331: case 332: case 333: case 334: { // READ/WRITE_PORT_BUFFER_*
		std::uint32_t buffer = 0, count = 0; if (!ReadStack(0, a) || !ReadStack(1, buffer) || !ReadStack(2, count)) return Unsupported(ordinal); const std::uint32_t width = (ordinal == 329 || ordinal == 332) ? 1 : (ordinal == 330 || ordinal == 333) ? 2 : 4; if (!IsRangeValid(buffer, static_cast<std::size_t>(count) * width)) return Unsupported(ordinal); const bool writePort = ordinal >= 332; for (std::uint32_t i = 0; i < count; ++i) { if (writePort) { std::uint32_t value = 0; if (width == 1) { std::uint8_t v = 0; Read(buffer + i, v); value = v; } else if (width == 2) { std::uint16_t v = 0; Read(buffer + i * 2, v); value = v; } else Read(buffer + i * 4, value); CxbxUwpWriteHardwarePort(a, value, width); } else { const std::uint32_t value = CxbxUwpReadHardwarePort(a, width); if (width == 1) Write(buffer + i, static_cast<std::uint8_t>(value)); else if (width == 2) Write(buffer + i * 2, static_cast<std::uint16_t>(value)); else Write(buffer + i * 4, value); } } FinishStdcall(3); break;
	}
	case 335: { // XcSHAInit
		if (m_cryptoOverrides[0]) { m_regs->eip = m_cryptoOverrides[0]; break; } if (!ReadStack(0, a) || !IsRangeValid(a, 24 + sizeof(SHA1_CTX))) return Unsupported(ordinal); SHA1Init(reinterpret_cast<SHA1_CTX*>(GuestPointer(a + 24, sizeof(SHA1_CTX)))); FinishStdcall(1); break;
	}
	case 336: { // XcSHAUpdate
		if (m_cryptoOverrides[1]) { m_regs->eip = m_cryptoOverrides[1]; break; } if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(a, 24 + sizeof(SHA1_CTX)) || !IsRangeValid(b, c)) return Unsupported(ordinal); SHA1Update(reinterpret_cast<SHA1_CTX*>(GuestPointer(a + 24, sizeof(SHA1_CTX))), GuestPointer(b, c), c); FinishStdcall(3); break;
	}
	case 337: { // XcSHAFinal
		if (m_cryptoOverrides[2]) { m_regs->eip = m_cryptoOverrides[2]; break; } if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 24 + sizeof(SHA1_CTX)) || !IsRangeValid(b, 20)) return Unsupported(ordinal); SHA1Final(GuestPointer(b, 20), reinterpret_cast<SHA1_CTX*>(GuestPointer(a + 24, sizeof(SHA1_CTX)))); FinishStdcall(2); break;
	}
	case 338: { // XcRC4Key
		if (m_cryptoOverrides[3]) { m_regs->eip = m_cryptoOverrides[3]; break; } if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !b || !IsRangeValid(a, sizeof(Rc4Context)) || !IsRangeValid(c, b)) return Unsupported(ordinal); Rc4Initialise(reinterpret_cast<Rc4Context*>(GuestPointer(a, sizeof(Rc4Context))), GuestPointer(c, b), b, 0); FinishStdcall(3); break;
	}
	case 339: { // XcRC4Crypt
		if (m_cryptoOverrides[4]) { m_regs->eip = m_cryptoOverrides[4]; break; } if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(a, sizeof(Rc4Context)) || !IsRangeValid(c, b)) return Unsupported(ordinal); auto* context = reinterpret_cast<Rc4Context*>(GuestPointer(a, sizeof(Rc4Context))); auto* data = GuestPointer(c, b); Rc4Xor(context, data, data, b); FinishStdcall(3); break;
	}
	case 340: { // XcHMAC
		if (m_cryptoOverrides[5]) { m_regs->eip = m_cryptoOverrides[5]; break; } std::uint32_t keyLength = 0, data = 0, dataLength = 0, data2 = 0, data2Length = 0, output = 0; if (!ReadStack(0, a) || !ReadStack(1, keyLength) || !ReadStack(2, data) || !ReadStack(3, dataLength) || !ReadStack(4, data2) || !ReadStack(5, data2Length) || !ReadStack(6, output) || !IsRangeValid(a, keyLength) || !IsRangeValid(data, dataLength) || !IsRangeValid(data2, data2Length) || !IsRangeValid(output, 20)) return Unsupported(ordinal); const auto* keyInput = GuestPointer(a, keyLength); const auto* dataInput = GuestPointer(data, dataLength); const auto* data2Input = GuestPointer(data2, data2Length); auto* outputBytes = GuestPointer(output, 20); std::uint8_t key[64] = {}, inner[20] = {}, pad[64] = {}; if (keyLength > 64) { SHA1_CTX hash = {}; SHA1Init(&hash); SHA1Update(&hash, keyInput, keyLength); SHA1Final(key, &hash); keyLength = 20; } else std::memcpy(key, keyInput, keyLength); for (unsigned i = 0; i < 64; ++i) pad[i] = key[i] ^ 0x36; SHA1_CTX hash = {}; SHA1Init(&hash); SHA1Update(&hash, pad, 64); if (dataLength) SHA1Update(&hash, dataInput, dataLength); if (data2Length) SHA1Update(&hash, data2Input, data2Length); SHA1Final(inner, &hash); for (unsigned i = 0; i < 64; ++i) pad[i] = key[i] ^ 0x5C; SHA1Init(&hash); SHA1Update(&hash, pad, 64); SHA1Update(&hash, inner, 20); SHA1Final(outputBytes, &hash); FinishStdcall(7); break;
	}
	case 341: case 342: case 343: case 344: { // Xc public/private-key services
		const std::size_t vectorIndex = ordinal - 335; if (m_cryptoOverrides[vectorIndex]) { m_regs->eip = m_cryptoOverrides[vectorIndex]; break; }
		if (!ReadStack(0, a)) return Unsupported(ordinal); std::uint32_t keyAddress = a; if (ordinal == 344 && !ReadStack(1, keyAddress)) return Unsupported(ordinal); if (!IsRangeValid(keyAddress, 20)) return Unsupported(ordinal); std::uint32_t modulusLast = 0; Read(keyAddress + 12, modulusLast); const std::uint32_t keyLength = modulusLast + 1;
		if (!keyLength || keyLength > 512 || !IsRangeValid(keyAddress, 20 + keyLength)) { m_regs->eax = 0; FinishStdcall(ordinal == 343 ? 1 : 3); break; }
		if (ordinal == 343) { m_regs->eax = keyLength; FinishStdcall(1); break; }
		if (ordinal != 344 && (!ReadStack(1, b) || !ReadStack(2, c))) return Unsupported(ordinal); if (ordinal == 344 && (!ReadStack(2, c) || !IsRangeValid(a, keyLength) || !IsRangeValid(c, 20))) return Unsupported(ordinal); if (ordinal != 344 && (!IsRangeValid(b, keyLength) || !IsRangeValid(c, keyLength))) return Unsupported(ordinal);
		BigWords modulus = BytesToWords(GuestPointer(keyAddress + 20, keyLength), keyLength), exponent; if (ordinal == 342) { if (!IsRangeValid(keyAddress + 20 + keyLength + 8, keyLength)) { m_regs->eax = 0; FinishStdcall(3); break; } exponent = BytesToWords(GuestPointer(keyAddress + 20 + keyLength + 8, keyLength), keyLength); } else { std::uint32_t publicExponent = 0; Read(keyAddress + 16, publicExponent); exponent = { publicExponent }; }
		if (ordinal == 344) { std::vector<std::uint8_t> decrypted(keyLength); WordsToBytes(BigModExp(BytesToWords(GuestPointer(a, keyLength), keyLength), exponent, modulus), decrypted.data(), keyLength); static const std::uint8_t digestInfo[][15] = { { 0x0F,0x14,0x04,0x00,0x05,0x1A,0x02,0x03,0x0E,0x2B,0x05,0x06,0x09,0x30,0x21 }, { 0x0D,0x14,0x04,0x1A,0x02,0x03,0x0E,0x2B,0x05,0x06,0x07,0x30,0x1F } }; const auto* digest = GuestPointer(c, 20); bool valid = std::equal(digest, digest + 20, decrypted.rbegin()); if (valid) { std::size_t pos = 20; bool oid = false; for (const auto& table : digestInfo) { const std::size_t n = table[0]; if (pos + n <= decrypted.size() && std::memcmp(decrypted.data() + pos, table + 1, n) == 0) { pos += n; oid = true; break; } } valid = oid && pos < decrypted.size() && decrypted[pos++] == 0; while (valid && pos + 2 < decrypted.size()) valid = decrypted[pos++] == 0xFF; valid = valid && pos + 2 == decrypted.size() && decrypted[pos] == 1 && decrypted[pos + 1] == 0; } m_regs->eax = valid ? 1 : 0; }
		else { BigWords input = BytesToWords(GuestPointer(b, keyLength), keyLength); WordsToBytes(BigModExp(input, exponent, modulus), GuestPointer(c, keyLength), keyLength); m_regs->eax = 1; }
		FinishStdcall(3); break;
	}
	case 345: { // XcModExp
		if (m_cryptoOverrides[10]) { m_regs->eip = m_cryptoOverrides[10]; break; } std::uint32_t base = 0, exponent = 0, modulus = 0, words = 0; if (!ReadStack(0, a) || !ReadStack(1, base) || !ReadStack(2, exponent) || !ReadStack(3, modulus) || !ReadStack(4, words) || !words || words > 128 || !IsRangeValid(a, words * 4) || !IsRangeValid(base, words * 4) || !IsRangeValid(exponent, words * 4) || !IsRangeValid(modulus, words * 4)) return Unsupported(ordinal); WordsToBytes(BigModExp(BytesToWords(GuestPointer(base, words * 4), words * 4), BytesToWords(GuestPointer(exponent, words * 4), words * 4), BytesToWords(GuestPointer(modulus, words * 4), words * 4)), GuestPointer(a, words * 4), words * 4); m_regs->eax = 1; FinishStdcall(5); break;
	}
	case 346: { // XcDESKeyParity
		if (m_cryptoOverrides[11]) { m_regs->eip = m_cryptoOverrides[11]; break; } if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, b)) return Unsupported(ordinal); mbedtls_des_key_set_parity(GuestPointer(a, b), b); FinishStdcall(2); break;
	}
	case 347: { // XcKeyTable
		if (m_cryptoOverrides[12]) { m_regs->eip = m_cryptoOverrides[12]; break; } if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c)) return Unsupported(ordinal); const std::uint32_t tableSize = a ? sizeof(mbedtls_des3_context) : sizeof(mbedtls_des_context), keySize = a ? 24 : 8; if (!IsRangeValid(b, tableSize) || !IsRangeValid(c, keySize)) return Unsupported(ordinal); if (a) mbedtls_des3_set3key_enc(reinterpret_cast<mbedtls_des3_context*>(GuestPointer(b, tableSize)), GuestPointer(c, keySize)); else mbedtls_des_setkey_enc(reinterpret_cast<mbedtls_des_context*>(GuestPointer(b, tableSize)), GuestPointer(c, keySize)); FinishStdcall(3); break;
	}
	case 348: { // XcBlockCrypt
		if (m_cryptoOverrides[13]) { m_regs->eip = m_cryptoOverrides[13]; break; } std::uint32_t output = 0, input = 0, table = 0, operation = 0; if (!ReadStack(0, a) || !ReadStack(1, output) || !ReadStack(2, input) || !ReadStack(3, table) || !ReadStack(4, operation) || !IsRangeValid(output, 8) || !IsRangeValid(input, 8) || !IsRangeValid(table, a ? sizeof(mbedtls_des3_context) : sizeof(mbedtls_des_context))) return Unsupported(ordinal); const std::uint32_t tableSize = a ? sizeof(mbedtls_des3_context) : sizeof(mbedtls_des_context); if (a) mbedtls_des3_crypt_ecb(reinterpret_cast<mbedtls_des3_context*>(GuestPointer(table, tableSize)), GuestPointer(input, 8), GuestPointer(output, 8), operation); else mbedtls_des_crypt_ecb(reinterpret_cast<mbedtls_des_context*>(GuestPointer(table, tableSize)), GuestPointer(input, 8), GuestPointer(output, 8), operation); FinishStdcall(5); break;
	}
	case 349: { // XcBlockCryptCBC
		if (m_cryptoOverrides[14]) { m_regs->eip = m_cryptoOverrides[14]; break; } std::uint32_t length = 0, output = 0, input = 0, table = 0, operation = 0, feedback = 0; if (!ReadStack(0, a) || !ReadStack(1, length) || !ReadStack(2, output) || !ReadStack(3, input) || !ReadStack(4, table) || !ReadStack(5, operation) || !ReadStack(6, feedback) || (length & 7) || !IsRangeValid(output, length) || !IsRangeValid(input, length) || !IsRangeValid(feedback, 8) || !IsRangeValid(table, a ? sizeof(mbedtls_des3_context) : sizeof(mbedtls_des_context))) return Unsupported(ordinal); const std::uint32_t tableSize = a ? sizeof(mbedtls_des3_context) : sizeof(mbedtls_des_context); if (a) mbedtls_des3_crypt_cbc(reinterpret_cast<mbedtls_des3_context*>(GuestPointer(table, tableSize)), operation, length, GuestPointer(feedback, 8), GuestPointer(input, length), GuestPointer(output, length)); else mbedtls_des_crypt_cbc(reinterpret_cast<mbedtls_des_context*>(GuestPointer(table, tableSize)), operation, length, GuestPointer(feedback, 8), GuestPointer(input, length), GuestPointer(output, length)); FinishStdcall(7); break;
	}
	case 350: // XcCryptService is a ROM-defined dummy: zero, arguments unchanged.
		if (m_cryptoOverrides[15]) { m_regs->eip = m_cryptoOverrides[15]; break; } m_regs->eax = 0; FinishStdcall(2); break;
	case 351: { // XcUpdateCrypto
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 64) || (b && !IsRangeValid(b, 64))) return Unsupported(ordinal); for (std::uint32_t i = 0; i < 16; ++i) { std::uint32_t routine = 0; Read(a + i * 4, routine); if (routine) m_cryptoOverrides[i] = routine; if (b) Write(b + i * 4, StubBase + (CryptoRomBaseOrdinal + i) * StubStride); } FinishStdcall(2); break;
	}
	case 352: { // RtlRip
		std::uint32_t expression = 0, message = 0; if (!ReadStack(0, a) || !ReadStack(1, expression) || !ReadStack(2, message)) return Unsupported(ordinal); auto guestString = [this](std::uint32_t address) { std::string value; for (std::uint32_t i = 0; address && i < 512; ++i) { std::uint8_t character = 0; if (!Read(address + i, character) || !character) break; value.push_back(static_cast<char>(character)); } return value; }; const std::string text = "[RtlRip] " + guestString(a) + ": " + guestString(expression) + " (" + guestString(message) + ")\r\n"; if (m_logger) m_logger(text.c_str()); RaiseGuestException(0x80000003u, 0, "RtlRip"); break;
	}
	case 358: // HalIsResetOrShutdownPending
		m_regs->eax = m_shutdownPending ? 1 : 0; FinishStdcall(0); break;
	case 359: { // IoMarkIrpMustComplete
		if (!ReadStack(0, a) || !IsRangeValid(a, 8)) return Unsupported(ordinal); std::uint32_t flags = 0; Read(a + 4, flags); const bool alreadySet = (flags & 0x80000000u) != 0; Write(a + 4, flags | 0x80000000u); m_regs->eax = alreadySet ? 1 : 0; FinishStdcall(1); break;
	}
	case 360: // HalInitiateShutdown
		m_shutdownPending = true; m_smbusValues[(0x20u << 8) | 2u] = 0x80; m_regs->eax = StatusSuccess; FinishStdcall(0);
		StartShutdownNotifications(false); break;
	case 361: case 362: case 363: case 364: { // Rtl[s/v]snprintf / Rtl[s/v]sprintf, cdecl
		std::uint32_t capacity = XboxRamSize, format = 0, arguments = 0; if (!ReadStack(0, a)) return Unsupported(ordinal);
		if (ordinal == 361 || ordinal == 363) { if (!ReadStack(1, capacity) || !ReadStack(2, format)) return Unsupported(ordinal); if (ordinal == 361) arguments = m_regs->esp + 16; else if (!ReadStack(3, arguments)) return Unsupported(ordinal); }
		else { if (!ReadStack(1, format)) return Unsupported(ordinal); if (ordinal == 362) arguments = m_regs->esp + 12; else if (!ReadStack(2, arguments)) return Unsupported(ordinal); capacity = a < XboxRamSize ? XboxRamSize - a : 0; }
		std::string formatted; const int written = FormatGuestString(format, arguments, formatted); if (written < 0 || (capacity && !IsRangeValid(a, capacity))) { m_regs->eax = static_cast<std::uint32_t>(-1); FinishCdecl(); break; }
		if (capacity) { const std::size_t copy = (std::min<std::size_t>)(formatted.size(), capacity - 1); auto* output = GuestPointer(a, capacity); if (copy) std::memcpy(output, formatted.data(), copy); output[copy] = 0; }
		m_regs->eax = static_cast<std::uint32_t>(written); FinishCdecl(); break;
	}
	case 365: // HalEnableSecureTrayEject
		m_secureTrayEject = true; m_smbusValues[(0x20u << 8) | 0x19u] = 0; FinishStdcall(0); break;
	case 366: // HalWriteSMCScratchRegister
		if (!ReadStack(0, a)) return Unsupported(ordinal); m_smcScratch = a; m_smbusValues[(0x20u << 8) | 0x1Bu] = a & 0xFF; m_regs->eax = StatusSuccess; FinishStdcall(1); break;
	case 367: case 368: case 369: // Null/unused slots in known retail and debug kernel export tables.
		m_regs->eax = StatusSuccess; FinishStdcall(0); break;
	case 370: // XProfpControl
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal); m_profilerAction = a; m_profilerParameter = b; if (!a) m_profilerSamples = 0; m_regs->eax = StatusSuccess; FinishStdcall(2); break;
	case 371: // XProfpGetData
		m_regs->eax = StatusSuccess; FinishStdcall(0); break;
	case 372: // IrtClientInitFast
		m_irtActive = true; m_regs->eax = StatusSuccess; FinishStdcall(0); break;
	case 373: // IrtSweep
		if (m_irtActive) ++m_profilerSamples; m_regs->eax = m_irtActive ? StatusSuccess : StatusInvalidParameter; FinishStdcall(0); break;
	case 374: { // MmDbgAllocateMemory
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal); const std::uint32_t address = Allocate((a + 0xFFFu) & ~0xFFFu); if (address) m_allocationProtect[address] = b; m_regs->eax = address; FinishStdcall(2); break;
	}
	case 375: { // MmDbgFreeMemory
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal); const std::uint32_t allocated = AllocationSize(a); if (!allocated || (b && b > allocated)) m_regs->eax = 0; else { m_regs->eax = ((b ? b : allocated) + 0xFFFu) >> 12; Free(a); } FinishStdcall(2); break;
	}
	case 376: { // MmDbgQueryAvailablePages
		std::lock_guard<std::mutex> lock(m_memoryMutex); m_regs->eax = (m_poolLimit - m_poolCursor) >> 12; FinishStdcall(0); break;
	}
	case 377: { // MmDbgReleaseAddress
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(b, 4)) return Unsupported(ordinal); std::uint32_t base = 0, protect = 0; { std::lock_guard<std::mutex> lock(m_memoryMutex); for (const auto& item : m_allocations) if (a >= item.first && a < item.first + item.second) { base = item.first; protect = m_allocationProtect[item.first]; break; } if (base) m_allocationProtect[base] = PAGE_NOACCESS; } Write(b, protect); FinishStdcall(2); break;
	}
	case 378: { // MmDbgWriteCheck
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(b, 4)) return Unsupported(ordinal); std::uint32_t base = 0, savedProtect = 0; Read(b, savedProtect); { std::lock_guard<std::mutex> lock(m_memoryMutex); for (const auto& item : m_allocations) if (a >= item.first && a < item.first + item.second) { base = item.first; break; } if (base) m_allocationProtect[base] = savedProtect ? savedProtect : PAGE_READWRITE; } m_regs->eax = base ? a : 0; FinishStdcall(2); break;
	}
	case 98: { // KeConnectInterrupt
		if (!ReadStack(0, a) || !IsRangeValid(a, 112)) return Unsupported(ordinal);
		InterruptItem item = {}; item.address = a;
		std::uint16_t interruptMode = 0;
		Read(a, item.routine); Read(a + 4, item.context); Read(a + 8, item.busLevel); Read(a + 12, item.irql); Read(a + 18, interruptMode); item.mode = interruptMode;
		bool connected = false;
		if (item.busLevel <= 27 && item.routine && IsRangeValid(item.routine, 1)) {
			std::lock_guard<std::mutex> lock(m_interruptMutex);
			auto found = m_interrupts.find(item.busLevel);
			if (found == m_interrupts.end() || !found->second.connected || found->second.address == a) {
				item.connected = true; item.assertedSources = m_assertedDeviceSources[item.busLevel]; m_interrupts[item.busLevel] = item; m_enabledInterrupts |= 1u << item.busLevel; connected = true;
				if (item.assertedSources && std::find(m_pendingInterrupts.begin(), m_pendingInterrupts.end(), item.busLevel) == m_pendingInterrupts.end()) m_pendingInterrupts.push_back(item.busLevel);
			}
		}
		Write(a + 16, static_cast<std::uint8_t>(connected)); m_regs->eax = connected ? 1 : 0; FinishStdcall(1); break;
	}
	case 100: { // KeDisconnectInterrupt
		if (!ReadStack(0, a) || !IsRangeValid(a, 17)) return Unsupported(ordinal);
		std::uint32_t level = 0; Read(a + 8, level);
		{ std::lock_guard<std::mutex> lock(m_interruptMutex); auto found = m_interrupts.find(level); if (found != m_interrupts.end() && found->second.address == a) m_interrupts.erase(found); m_pendingInterrupts.erase(std::remove(m_pendingInterrupts.begin(), m_pendingInterrupts.end(), level), m_pendingInterrupts.end()); }
		if (level < 32) { std::lock_guard<std::mutex> lock(m_interruptMutex); m_enabledInterrupts &= ~(1u << level); }
		Write(a + 16, static_cast<std::uint8_t>(0)); FinishStdcall(1); break;
	}
	case 103: // KeGetCurrentIrql
		m_regs->eax = m_currentIrql; FinishStdcall(0); break;
	case 107: { // KeInitializeDpc
		const bool haveDpc = ReadStack(0, a);
		const bool haveRoutine = ReadStack(1, b);
		const bool haveContext = ReadStack(2, c);
		if (!haveDpc || !haveRoutine || !haveContext || !IsRangeValid(a, 28)) {
			if (m_logger) {
				char line[224] = {};
				sprintf_s(line, "[uwp-kernel:dpc:error] KeInitializeDpc invalido: Dpc=0x%08X Routine=0x%08X Context=0x%08X ESP=0x%08X pilha=%u/%u/%u.\r\n",
					a, b, c, m_regs->esp, haveDpc ? 1u : 0u, haveRoutine ? 1u : 0u, haveContext ? 1u : 0u);
				m_logger(line);
			}
			return Unsupported(ordinal);
		}
		FillGuestMemory(a, 0, 28); Write(a, static_cast<std::uint16_t>(0x13)); Write(a + 4, a + 4); Write(a + 8, a + 4); Write(a + 12, b); Write(a + 16, c); FinishStdcall(3); break;
	}
	case 109: { // KeInitializeInterrupt
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !ReadStack(3, d) || !IsRangeValid(a, 112)) return Unsupported(ordinal);
		std::uint32_t irql = 0, mode = 0, shared = 0;
		if (!ReadStack(4, irql) || !ReadStack(5, mode) || !ReadStack(6, shared)) return Unsupported(ordinal);
		FillGuestMemory(a, 0, 112); Write(a, b); Write(a + 4, c); Write(a + 8, d >= 0x30 ? d - 0x30 : d); Write(a + 12, irql);
		Write(a + 17, static_cast<std::uint8_t>(shared != 0)); Write(a + 18, static_cast<std::uint16_t>(mode)); FinishStdcall(7); break;
	}
	case 119: { // KeInsertQueueDpc
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(a, 28)) return Unsupported(ordinal);
		m_regs->eax = QueueDpc(a, b, c) ? 1 : 0; FinishStdcall(3); break;
	}
	case 121: // KeIsExecutingDpc
		m_regs->eax = m_dpcActive ? 1 : 0; FinishStdcall(0); break;
	case 104: // KeGetCurrentThread
		m_regs->eax = m_currentThread; FinishStdcall(0); break;
	case 125: { // KeQueryInterruptTime
		const auto elapsed = std::chrono::steady_clock::now() - m_kernelBootTime;
		SetReturn64(static_cast<std::uint64_t>(
			std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count() / 100));
		FinishStdcall(0); break;
	}
	case 126: { // KeQueryPerformanceCounter
		// Xbox kernel performance services use the 3.375 MHz ACPI clock, not the
		// host QPC frequency (XAPI's user-mode counter uses the CPU/TSC clock).
		const auto elapsed = std::chrono::steady_clock::now() - m_kernelBootTime;
		const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count();
		SetReturn64(static_cast<std::uint64_t>(nanoseconds) * 3375000ull / 1000000000ull);
		FinishStdcall(0); break;
	}
	case 127: { // KeQueryPerformanceFrequency
		SetReturn64(3375000ull); FinishStdcall(0); break;
	}
	case 128: { // KeQuerySystemTime
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		FILETIME time = {}; GetSystemTimeAsFileTime(&time);
		const std::uint64_t value = ((static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime) + m_systemTimeOffset;
		if (!Write(a, value)) return Unsupported(ordinal);
		m_regs->eax = 0; FinishStdcall(1); break;
	}
	case 129: case 130: { // KeRaiseIrqlToDpcLevel / KeRaiseIrqlToSynchLevel
		const std::uint8_t previous = m_currentIrql;
		const std::uint8_t requested = static_cast<std::uint8_t>(ordinal == 129 ? 2 : 28);
		if (requested < previous) {
			SetCurrentIrql(0);
			if (m_logger) m_logger("[uwp-kernel:bugcheck] KfRaiseIrql: IRQL_NOT_GREATER_OR_EQUAL (0x00000009).\r\n");
			TerminateCurrentThread(0x00000009u);
			break;
		}
		SetCurrentIrql(requested);
		m_regs->eax = previous; FinishStdcall(0); break;
	}
	case 137: { // KeRemoveQueueDpc
		if (!ReadStack(0, a) || !IsRangeValid(a, 3)) return Unsupported(ordinal);
		auto found = std::find_if(m_dpcQueue.begin(), m_dpcQueue.end(), [a](const DpcItem& item) { return item.address == a; });
		if (found != m_dpcQueue.end()) {
			std::uint32_t next = 0, previous = 0; Read(a + 4, next); Read(a + 8, previous);
			if (next && previous && IsRangeValid(next, 8) && IsRangeValid(previous, 8)) { Write(previous, next); Write(next + 4, previous); }
			Write(a + 4, a + 4); Write(a + 8, a + 4);
			m_dpcQueue.erase(found); Write(a + 2, static_cast<std::uint8_t>(0)); m_regs->eax = 1;
		} else m_regs->eax = 0;
		if (m_dpcQueue.empty()) m_softwareInterrupts &= ~(1u << 2); FinishStdcall(1); break;
	}
	case 151: // KeStallExecutionProcessor
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		if (a) std::this_thread::sleep_for(std::chrono::microseconds((std::min)(a, 100000u)));
		FinishStdcall(1); break;
	case 152: { // KeSuspendThread
		if (!ReadStack(0, a)) return Unsupported(ordinal); auto* thread = FindThreadByGuestAddress(a);
		if (!thread) { m_regs->eax = 0; FinishStdcall(1); break; }
		m_regs->eax = thread->suspendCount;
		if (thread->suspendCount >= 0x7F) { RaiseGuestException(0xC000004Au, 1, "KeSuspendThread"); break; }
		std::uint8_t apcQueueable = 0; Read(thread->guestThread + 0x4B, apcQueueable);
		if (!apcQueueable) { FinishStdcall(1); break; }
		++thread->suspendCount; Write(thread->guestThread + 0x75, static_cast<std::uint8_t>(thread->suspendCount));
		if (thread->suspendCount == 1) { Write(thread->guestThread + 0xF4, 0u); Write(thread->guestThread + 0xCB, static_cast<std::uint8_t>(1)); }
		FinishStdcall(1);
		Write(thread->guestThread + 0x2C, static_cast<std::uint8_t>(5));
		if (thread == &m_threads[m_currentThreadIndex]) { thread->regs = *m_regs; thread->state = ThreadState::Suspended; SwitchThread(false); }
		else if (thread->state == ThreadState::Runnable || thread->state == ThreadState::Running) thread->state = ThreadState::Suspended;
		break;
	}
	case 153: { // KeSynchronizeExecution
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !b || !IsRangeValid(b, 1)) return Unsupported(ordinal);
		std::uint32_t syncIrql = 28; if (a && IsRangeValid(a + 12, 4)) Read(a + 12, syncIrql);
		FinishStdcall(3); m_synchronizeResume = *m_regs; m_savedSynchronizeIrql = m_currentIrql;
		m_synchronizeActive = true;
		SetCurrentIrql(static_cast<std::uint8_t>((std::min)((std::max)(syncIrql, static_cast<std::uint32_t>(m_currentIrql)), 31u)));
		m_regs->esp -= 4; Write(m_regs->esp, c); m_regs->esp -= 4; Write(m_regs->esp, StubBase + SynchronizeReturnOrdinal * StubStride); m_regs->eip = b; break;
	}
	case 158: { // KeWaitForMultipleObjects
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c)) return Unsupported(ordinal);
		if (a == 0 || a > 64 || !IsRangeValid(b, a * 4)) { m_regs->eax = StatusInvalidParameter; FinishStdcall(8); break; }
		std::vector<ObjectPtr> objects; objects.reserve(a);
		for (std::uint32_t i = 0; i < a; ++i) { std::uint32_t address = 0; Read(b + i * 4, address); auto object = GetDispatcherObject(address); if (!object) { m_regs->eax = StatusInvalidHandle; FinishStdcall(8); return; } if (std::any_of(objects.begin(), objects.end(), [&object](const ObjectPtr& existing) { return existing.get() == object.get(); })) { m_regs->eax = StatusInvalidParameter; FinishStdcall(8); return; } objects.push_back(object); }
		std::uint32_t waitReason = 0, waitMode = 0, timeout = 0, alertable = 0, waitBlocks = 0;
		if (!ReadStack(3, waitReason) || !ReadStack(4, waitMode) || !ReadStack(5, alertable) ||
			!ReadStack(6, timeout) || !ReadStack(7, waitBlocks)) return Unsupported(ordinal);
		if (waitMode > 1) { m_regs->eax = StatusInvalidParameter; FinishStdcall(8); break; }
		if (waitBlocks && !IsRangeValid(waitBlocks, a * 24)) { m_regs->eax = StatusInvalidParameter; FinishStdcall(8); break; }
		FinishStdcall(8); ScheduleWait(std::move(objects), c == 0, alertable != 0, timeout,
			static_cast<std::uint8_t>(waitMode), static_cast<std::uint8_t>(waitReason), waitBlocks); break;
	}
	case 159: { // KeWaitForSingleObject
		std::uint32_t waitReason = 0, waitMode = 0, alertable = 0; if (!ReadStack(0, a) || !ReadStack(1, waitReason) || !ReadStack(2, waitMode) || !ReadStack(3, alertable) || !ReadStack(4, b)) return Unsupported(ordinal);
		if (waitMode > 1) { m_regs->eax = StatusInvalidParameter; FinishStdcall(5); break; }
		auto object = GetDispatcherObject(a);
		if (!object) { m_regs->eax = StatusInvalidHandle; FinishStdcall(5); break; }
		FinishStdcall(5); ScheduleWait({ object }, false, alertable != 0, b,
			static_cast<std::uint8_t>(waitMode), static_cast<std::uint8_t>(waitReason)); break;
	}
	case 160: { // KfRaiseIrql, fastcall
		const std::uint8_t previous = m_currentIrql;
		// KIRQL is an unsigned byte.  On x86 fastcall the compiler is only
		// required to load CL; the upper 24 bits of ECX remain unspecified.
		const std::uint8_t requested = (std::min)(static_cast<std::uint8_t>(m_regs->ecx), static_cast<std::uint8_t>(31));
		if (requested < previous) {
			SetCurrentIrql(0);
			if (m_logger) m_logger("[uwp-kernel:bugcheck] KfRaiseIrql: IRQL_NOT_GREATER_OR_EQUAL (0x00000009).\r\n");
			TerminateCurrentThread(0x00000009u);
			break;
		}
		SetCurrentIrql(requested);
		m_regs->eax = previous; FinishFastcall(); break;
	}
	case 161: { // KfLowerIrql, fastcall
		const std::uint8_t requested = (std::min)(static_cast<std::uint8_t>(m_regs->ecx), static_cast<std::uint8_t>(31));
		if (requested > m_currentIrql && m_logger) m_logger("[uwp-kernel:irql] KfLowerIrql recebeu nivel superior ao atual.\r\n");
		SetCurrentIrql(requested); FinishFastcall();
		if (!DeliverPendingInterrupt() && !DeliverPendingDpc() && !m_threads.empty())
			DeliverPendingApc(m_threads[m_currentThreadIndex]);
		break;
	}
	case 163: { // KiUnlockDispatcherDatabase, fastcall
		const std::uint8_t requested = (std::min)(static_cast<std::uint8_t>(m_regs->ecx), static_cast<std::uint8_t>(31));
		SetCurrentIrql(requested); FinishFastcall();
		if (!DeliverPendingInterrupt() && !DeliverPendingDpc()) {
			if (!m_threads.empty() && DeliverPendingApc(m_threads[m_currentThreadIndex])) break;
			OnTimeslice();
		}
		break;
	}
	case 165: // MmAllocateContiguousMemory
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		m_regs->eax = AllocateAligned(a, 4096, 0, m_poolLimit - 1, PAGE_READWRITE); FinishStdcall(1); break;
	case 166: // MmAllocateContiguousMemoryEx(size, low, high, alignment, protect)
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !ReadStack(3, d)) return Unsupported(ordinal);
		{ std::uint32_t protect = PAGE_READWRITE; ReadStack(4, protect); m_regs->eax = AllocateAligned(a, d ? d : 4096, b, c, protect); }
		FinishStdcall(5); break;
	case 167: // MmAllocateSystemMemory(size, protect)
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal);
		m_regs->eax = AllocateAligned(a, 4096, 0, m_poolLimit - 1, b); FinishStdcall(2); break;
	case 168: // MmClaimGpuInstanceMemory(size, paddingOut)
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal);
		if (b && !Write(b, 0x10000u)) return Unsupported(ordinal);
		if (a != 0xFFFFFFFFu) {
			if (a > 0x10000u) { m_regs->eax = 0; FinishStdcall(2); break; }
			m_gpuInstanceMemoryBytes = (a + 0xFFFu) & ~0xFFFu;
			const std::uint32_t retainedBase = 0x03FF0000u - m_gpuInstanceMemoryBytes;
			std::lock_guard<std::mutex> lock(m_memoryMutex);
			if (retainedBase > 0x03FE0000u) SetPageRange(0x03FE0000u,
				retainedBase - 0x03FE0000u, XboxMemReserve, PAGE_NOACCESS);
			if (m_gpuInstanceMemoryBytes) SetPageRange(retainedBase,
				m_gpuInstanceMemoryBytes, XboxMemCommit, PAGE_READWRITE);
		}
		m_regs->eax = 0x03FF0000u; FinishStdcall(2); break;
	case 169: // MmCreateKernelStack(size, debuggerThread)
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		{ const std::uint32_t usable = (a + 0xFFFu) & ~0xFFFu;
			const std::uint32_t allocation = AllocateAligned(usable + 0x1000u, 4096, 0, m_poolLimit - 1, PAGE_READWRITE);
			if (allocation) { std::lock_guard<std::mutex> lock(m_memoryMutex); SetPageRange(allocation, 0x1000u, XboxMemReserve, PAGE_NOACCESS); }
			const std::uint32_t top = allocation ? allocation + 0x1000u + usable : 0;
			if (top) m_kernelStacks[top] = allocation; m_regs->eax = top; }
		FinishStdcall(2); break;
	case 170: // MmDeleteKernelStack(stackBase, stackLimit)
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal);
		{ auto stack = m_kernelStacks.find(a); std::uint32_t allocation = stack == m_kernelStacks.end() ? 0 : stack->second;
			if (!allocation && b >= 0x1000u && AllocationSize(b - 0x1000u)) allocation = b - 0x1000u;
			if (stack != m_kernelStacks.end()) m_kernelStacks.erase(stack); if (allocation) Free(allocation); }
		FinishStdcall(2); break;
	case 171: // MmFreeContiguousMemory
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		Free(a); FinishStdcall(1); break;
	case 172: // MmFreeSystemMemory(address, bytes)
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal);
		{ const std::uint32_t allocated = AllocationSize(a);
			m_regs->eax = allocated ? (((std::min)(b ? b : allocated, allocated) + 0xFFFu) >> 12) : 0;
			if (allocated) Free(a); }
		FinishStdcall(2); break;
	case 173: // MmGetPhysicalAddress
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		m_regs->eax = a; FinishStdcall(1); break;
	case 174: // MmIsAddressValid
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		m_regs->eax = IsRangeValid(a, 1) && IsAddressMapped(a) ? 1 : 0; FinishStdcall(1); break;
	case 175: { // MmLockUnlockBufferPages
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !b || !IsRangeValid(a, b)) return Unsupported(ordinal);
		const std::uint32_t first = a & ~0xFFFu;
		const std::uint64_t last = (static_cast<std::uint64_t>(a) + b + 0xFFFu) & ~0xFFFull;
		bool invalid = false;
		{
			std::lock_guard<std::mutex> lock(m_memoryMutex);
			for (std::uint32_t page = first; page < last; page += 0x1000) {
				auto state = m_pageState.find(page);
				if (page >= m_imageEndAddress && (state == m_pageState.end() || state->second != XboxMemCommit)) { invalid = true; break; }
			}
			if (!invalid) for (std::uint32_t page = first; page < last; page += 0x1000) {
				auto& count = m_pageLockCount[page];
				if (c) { if (count) --count; } else if (count != 0xFFFFFFFFu) ++count;
			}
		}
		if (invalid) { RaiseGuestException(0xC0000005u, 3, "MmLockUnlockBufferPages"); break; }
		FinishStdcall(3); break;
	}
	case 176: { // MmLockUnlockPhysicalPage
		if (!ReadStack(0, a) || !ReadStack(1, b) || a >= XboxRamSize) return Unsupported(ordinal);
		const std::uint32_t page = a & ~0xFFFu; std::lock_guard<std::mutex> lock(m_memoryMutex);
		auto& count = m_pageLockCount[page]; if (b) { if (count) --count; } else if (count != 0xFFFFFFFFu) ++count;
		FinishStdcall(2); break;
	}
	case 177: { // MmMapIoSpace(physical, length, protect) -- Xbox PHYSICAL_ADDRESS is 32-bit
		std::uint32_t physical = 0, length = 0, protect = 0; if (!ReadStack(0, physical) || !ReadStack(1, length) || !ReadStack(2, protect) || !length) return Unsupported(ordinal);
		const auto fitsRange = [physical, length](std::uint32_t base, std::uint32_t size) {
			return physical >= base && static_cast<std::uint64_t>(physical) + length <= static_cast<std::uint64_t>(base) + size;
		};
		const bool directMapped = static_cast<std::uint64_t>(physical) + length <= XboxRamSize ||
			fitsRange(CxbxUwpNv2aProducer::MmioBase, CxbxUwpNv2aProducer::MmioSize) ||
			fitsRange(CxbxUwpDeviceBus::MmioBase, CxbxUwpDeviceBus::MmioSize) ||
			fitsRange(CxbxUwpDeviceBus::McpxBase, CxbxUwpDeviceBus::McpxSize);
		const std::uint32_t mapped = directMapped ? physical : AllocateAligned(length, 4096, 0, m_poolLimit - 1, protect);
		if (mapped && mapped != physical) m_ioMappings[mapped] = { physical, length };
		m_regs->eax = mapped; FinishStdcall(3); break;
	}
	case 178: // MmPersistContiguousMemory
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(a, b)) return Unsupported(ordinal); m_persistedAllocations[a] = c != 0; FinishStdcall(3); break;
	case 179: // MmQueryAddressProtect
		if (!ReadStack(0, a)) return Unsupported(ordinal); { std::lock_guard<std::mutex> lock(m_memoryMutex); auto found = m_pageProtect.find(a & ~0xFFFu); m_regs->eax = found == m_pageProtect.end() ? (IsRangeValid(a, 1) && a < m_imageEndAddress ? PAGE_EXECUTE_READ : PAGE_NOACCESS) : found->second; } FinishStdcall(1); break;
	case 180: // MmQueryAllocationSize
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		m_regs->eax = AllocationSize(a); FinishStdcall(1); break;
	case 181: { // MmQueryStatistics
		if (!ReadStack(0, a) || !IsRangeValid(a, 36)) return Unsupported(ordinal);
		std::uint32_t length = 0; Read(a, length);
		if (length != 36) m_regs->eax = StatusInvalidParameter;
		else {
			std::uint32_t allocationPages = 0, reservedPages = 0, stackPages = 0;
			std::unordered_set<std::uint32_t> stackAllocations;
			{
				std::lock_guard<std::mutex> lock(m_memoryMutex);
				for (const auto& allocation : m_allocations) allocationPages += (allocation.second + 0xFFFu) >> 12;
				for (const auto& page : m_pageState) if (page.second == XboxMemReserve) ++reservedPages;
				for (const auto& stack : m_kernelStacks) stackAllocations.insert(stack.second);
				for (const auto& thread : m_threads) if (thread.stackAllocation) stackAllocations.insert(thread.stackAllocation);
				for (const std::uint32_t allocation : stackAllocations) {
					auto found = m_allocations.find(allocation);
					if (found != m_allocations.end()) stackPages += (found->second + 0xFFFu) >> 12;
				}
			}
			const std::uint32_t imagePages = (m_imageEndAddress + 0xFFFu) >> 12;
			const std::uint32_t totalPages = XboxRamSize >> 12;
			const std::uint32_t committedPages = (std::min)(totalPages, allocationPages + imagePages);
			const std::uint32_t poolPages = allocationPages > stackPages ? allocationPages - stackPages : 0;
			Write(a + 4, totalPages);
			Write(a + 8, totalPages - committedPages);
			Write(a + 12, committedPages << 12);
			Write(a + 16, reservedPages << 12);
			Write(a + 20, m_fscCachePages);
			Write(a + 24, poolPages);
			Write(a + 28, stackPages);
			Write(a + 32, imagePages);
			m_regs->eax = StatusSuccess;
		}
		FinishStdcall(1); break;
	}
	case 182: // MmSetAddressProtect
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !b || !IsRangeValid(a, b)) return Unsupported(ordinal); { std::lock_guard<std::mutex> lock(m_memoryMutex); SetPageRange(a, b, XboxMemCommit, c); std::uint32_t base = 0, size = 0; for (const auto& item : m_allocations) if (a >= item.first && a < item.first + item.second) { base = item.first; size = item.second; break; } if (base && a == base && b >= size) m_allocationProtect[base] = c; } FinishStdcall(3); break;
	case 183: // MmUnmapIoSpace
		if (!ReadStack(0, a)) return Unsupported(ordinal); if (m_ioMappings.erase(a)) Free(a); FinishStdcall(2); break;
	case 184: { // NtAllocateVirtualMemory
		std::uint32_t zeroBits = 0, sizePointer = 0, allocationType = 0, protect = 0;
		if (!ReadStack(0, a) || !ReadStack(1, zeroBits) || !ReadStack(2, sizePointer) || !ReadStack(3, allocationType) || !ReadStack(4, protect) || !IsRangeValid(a, 4) || !IsRangeValid(sizePointer, 4)) return Unsupported(ordinal);
		std::uint32_t requested = 0; Read(a, requested); Read(sizePointer, b);
		if (!b || (allocationType & (XboxMemCommit | XboxMemReserve)) == 0 || zeroBits > 20) { m_regs->eax = StatusInvalidParameter; FinishStdcall(5); break; }
		const std::uint32_t offset = requested & 0xFFFu; b = (b + offset + 0xFFFu) & ~0xFFFu;
		std::uint32_t address = requested & ~0xFFFu, allocationBase = 0, allocationSize = 0;
		if ((allocationType & XboxMemReserve) != 0) {
			if (requested) address = requested & ~0xFFFFu;
			const std::uint32_t high = zeroBits ? ((0x7FFFFFFFu >> zeroBits) < m_poolLimit ? (0x7FFFFFFFu >> zeroBits) : m_poolLimit - 1) : m_poolLimit - 1;
			address = AllocateAligned(b, requested ? 0x1000u : 0x10000u, address, requested ? address + b - 1 : high, protect);
			if (address && (allocationType & XboxMemCommit) == 0) { std::lock_guard<std::mutex> lock(m_memoryMutex); SetPageRange(address, b, XboxMemReserve, PAGE_NOACCESS); }
		} else if (address && FindAllocation(address, allocationBase, allocationSize) && static_cast<std::uint64_t>(address) + b <= static_cast<std::uint64_t>(allocationBase) + allocationSize) {
			std::lock_guard<std::mutex> lock(m_memoryMutex); SetPageRange(address, b, XboxMemCommit, protect); FillGuestMemory(address, 0, b);
		} else address = 0;
		if (!address) m_regs->eax = StatusNoMemory; else { Write(a, address); Write(sizePointer, b); m_regs->eax = StatusSuccess; }
		FinishStdcall(5); break;
	}
	case 185: { // NtCancelTimer
		if (!ReadStack(0, a) || !ReadStack(1, b) || (b && !IsRangeValid(b, 1))) return Unsupported(ordinal); auto object = GetHandle(a); if (!object) m_regs->eax = StatusInvalidHandle; else if (object->kind != ObjectKind::Timer) m_regs->eax = 0xC0000024u; else { if (b) Write(b, static_cast<std::uint8_t>(object->signaled)); object->timerActive = false; object->signaled = false; if (object->guestAddress) Write(object->guestAddress + 3, static_cast<std::uint8_t>(0)); SyncDispatcherSignal(object); m_regs->eax = StatusSuccess; } FinishStdcall(2); break;
	}
	case 186: { // NtClearEvent
		if (!ReadStack(0, a)) return Unsupported(ordinal); auto object = GetHandle(a); if (!object) m_regs->eax = StatusInvalidHandle; else if (object->kind != ObjectKind::Event) m_regs->eax = 0xC0000024u; else { object->signaled = false; SyncDispatcherSignal(object); m_regs->eax = StatusSuccess; } FinishStdcall(1); break;
	}
	case 187: // NtClose
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		m_regs->eax = CloseGuestHandle(a); FinishStdcall(1); break;
	case 188: { // NtCreateDirectoryObject
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal);
		auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::Directory; object->objectType = DataAddress(240);
		m_regs->eax = CreateNamedHandle(object, b, a); FinishStdcall(2); break;
	}
	case 201: { // NtOpenDirectoryObject
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 4)) return Unsupported(ordinal);
		Write(a, 0u); std::wstring name; const std::uint32_t resolveStatus = ResolveObjectName(b, name);
		if (resolveStatus != StatusSuccess) m_regs->eax = resolveStatus;
		else { auto found = m_namedObjects.find(NormalizeObjectName(name)); if (found == m_namedObjects.end()) m_regs->eax = StatusObjectNameNotFound; else if (found->second->kind != ObjectKind::Directory || found->second->objectType != DataAddress(240)) m_regs->eax = 0xC0000024u; else m_regs->eax = CreateOutputHandle(found->second, a); }
		FinishStdcall(2); break;
	}
	case 189: { // NtCreateEvent
		std::uint32_t attributes = 0; if (!ReadStack(0, a) || !ReadStack(1, attributes) || !ReadStack(2, b) || !ReadStack(3, c)) return Unsupported(ordinal);
		if (b > 1) { m_regs->eax = StatusInvalidParameter; FinishStdcall(4); break; }
		auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::Event; object->objectType = DataAddress(16); object->manualReset = b == 0; object->signaled = c != 0;
		m_regs->eax = CreateNamedHandle(object, attributes, a); FinishStdcall(4); break;
	}
	case 190: { // NtCreateFile
		std::uint32_t access = 0, attrs = 0, iosb = 0, share = 0, disposition = 0, options = 0;
		if (!ReadStack(0, a) || !ReadStack(1, access) || !ReadStack(2, attrs) || !ReadStack(3, iosb) ||
			!ReadStack(6, share) || !ReadStack(7, disposition) || !ReadStack(8, options)) return Unsupported(ordinal);
		m_regs->eax = OpenGuestFile(a, access, attrs, iosb, share, disposition, options); FinishStdcall(9); break;
	}
	case 191: { // NtCreateIoCompletion
		std::uint32_t desiredAccess = 0, attributes = 0, count = 0;
		if (!ReadStack(0, a) || !ReadStack(1, desiredAccess) || !ReadStack(2, attributes) || !ReadStack(3, count) || !IsRangeValid(a, 4)) return Unsupported(ordinal);
		(void)desiredAccess;
		auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::IoCompletion; object->objectType = DataAddress(64); object->manualReset = true;
		object->limit = static_cast<std::int32_t>(count ? count : 1);
		m_regs->eax = CreateNamedHandle(object, attributes, a); FinishStdcall(4); break;
	}
	case 192: { // NtCreateMutant
		std::uint32_t attributes = 0; if (!ReadStack(0, a) || !ReadStack(1, attributes) || !ReadStack(2, b)) return Unsupported(ordinal);
		auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::Mutant; object->objectType = DataAddress(22); object->signaled = b == 0;
		if (b) { object->ownerThreadId = m_threads[m_currentThreadIndex].id; object->recursionCount = 1; }
		m_regs->eax = CreateNamedHandle(object, attributes, a); FinishStdcall(3); break;
	}
	case 193: { // NtCreateSemaphore
		std::uint32_t attributes = 0; if (!ReadStack(0, a) || !ReadStack(1, attributes) || !ReadStack(2, b) || !ReadStack(3, c)) return Unsupported(ordinal);
		if (static_cast<std::int32_t>(b) < 0 || static_cast<std::int32_t>(c) <= 0 || b > c) { m_regs->eax = StatusInvalidParameter; FinishStdcall(4); break; }
		auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::Semaphore; object->objectType = DataAddress(30); object->count = b; object->limit = c;
		m_regs->eax = CreateNamedHandle(object, attributes, a); FinishStdcall(4); break;
	}
	case 194: { // NtCreateTimer
		std::uint32_t attributes = 0; if (!ReadStack(0, a) || !ReadStack(1, attributes) || !ReadStack(2, b)) return Unsupported(ordinal);
		if (b > 1) { m_regs->eax = StatusInvalidParameter; FinishStdcall(3); break; }
		auto object = std::make_shared<KernelObject>(); object->kind = ObjectKind::Timer; object->objectType = DataAddress(31); object->manualReset = b == 0;
		m_regs->eax = CreateNamedHandle(object, attributes, a); FinishStdcall(3); break;
	}
	case 195: { // NtDeleteFile
		if (!ReadStack(0, a)) return Unsupported(ordinal); std::wstring path;
		if (!ResolveGuestPath(a, path)) m_regs->eax = StatusInvalidParameter;
		else m_regs->eax = DeleteFileFromAppW(path.c_str()) ? StatusSuccess : StatusFromWin32(GetLastError());
		FinishStdcall(1); break;
	}
	case 196: case 200: { // NtDeviceIoControlFile / NtFsControlFile
		std::uint32_t eventHandle = 0, apcRoutine = 0, apcContext = 0, iosb = 0, control = 0;
		std::uint32_t input = 0, inputLength = 0, output = 0, outputLength = 0;
		if (!ReadStack(0, a) || !ReadStack(1, eventHandle) || !ReadStack(2, apcRoutine) || !ReadStack(3, apcContext) ||
			!ReadStack(4, iosb) || !ReadStack(5, control) || !ReadStack(6, input) || !ReadStack(7, inputLength) ||
			!ReadStack(8, output) || !ReadStack(9, outputLength) || !IsRangeValid(iosb, 8) ||
			(inputLength && !IsRangeValid(input, inputLength)) ||
			(outputLength && !IsRangeValid(output, outputLength))) return Unsupported(ordinal);
		ObjectPtr completionEvent;
		if (eventHandle) completionEvent = GetHandle(eventHandle);
		if ((eventHandle && (!completionEvent || completionEvent->kind != ObjectKind::Event)) ||
			(apcRoutine && !IsRangeValid(apcRoutine, 1))) {
			const std::uint32_t failure = eventHandle && (!completionEvent || completionEvent->kind != ObjectKind::Event) ?
				StatusInvalidHandle : StatusInvalidParameter;
			WriteIoStatus(iosb, failure, 0); m_regs->eax = failure; FinishStdcall(10); break;
		}
		auto object = GetHandle(a); std::uint32_t status = object ? StatusInvalidDeviceRequest : StatusInvalidHandle, information = 0;
		if (object && ordinal == 196 && control == 0x70000 && outputLength >= 24 && IsRangeValid(output, 24)) {
			LARGE_INTEGER size = {}; if (object->nativeHandle != INVALID_HANDLE_VALUE) GetFileSizeEx(object->nativeHandle, &size);
			const std::uint64_t sectors = object->rawDevice ? 0x01400000ull : static_cast<std::uint64_t>((std::max)(1ll, size.QuadPart / 512));
			FillGuestMemory(output, 0, 24); Write(output, sectors);
			Write(output + 8, 12u); Write(output + 12, 1u); Write(output + 16, 1u); Write(output + 20, 512u);
			status = StatusSuccess; information = 24;
		} else if (object && ordinal == 196 && control == 0x74004 && outputLength >= 28 && IsRangeValid(output, 28)) {
			LARGE_INTEGER size = {}; if (object->nativeHandle != INVALID_HANDLE_VALUE) GetFileSizeEx(object->nativeHandle, &size);
			const std::uint32_t partition = object->partitionNumber;
			const std::uint64_t start = object->rawDevice && partition < XboxPartitionLbaStart.size() ? static_cast<std::uint64_t>(XboxPartitionLbaStart[partition]) * 512ull : 0ull;
			const std::uint64_t bytes = object->rawDevice ? XboxPartitionBytes(partition) : static_cast<std::uint64_t>(size.QuadPart);
			FillGuestMemory(output, 0, 28); Write(output, start); Write(output + 8, bytes);
			Write(output + 20, object->rawDevice ? partition : 1u); Write(output + 26, static_cast<std::uint8_t>(1)); status = StatusSuccess; information = 28;
		} else if (object && ordinal == 196 && control == 0x7405C && outputLength >= 8 && IsRangeValid(output, 8)) {
			LARGE_INTEGER size = {}; if (object->nativeHandle != INVALID_HANDLE_VALUE) GetFileSizeEx(object->nativeHandle, &size);
			Write(output, object->rawDevice ? XboxPartitionBytes(object->partitionNumber) : static_cast<std::uint64_t>(size.QuadPart)); status = StatusSuccess; information = 8;
		} else if (object && ordinal == 196 && (control == 0x74800 || control == 0x002D4800)) {
			status = StatusSuccess;
		} else if (object && ordinal == 196 && control == 0x002D1080 && outputLength >= 12 && IsRangeValid(output, 12)) {
			const bool optical = !m_gameRoot.empty() && object->path.compare(0, m_gameRoot.size(), m_gameRoot) == 0;
			Write(output, optical ? 2u : 7u); Write(output + 4, 0u); Write(output + 8, optical ? 0xFFFFFFFFu : 1u);
			status = StatusSuccess; information = 12;
		} else if (object && ordinal == 196 && control == 0x002D0C14 && outputLength >= 8 && IsRangeValid(output, 8)) {
			const bool optical = !m_gameRoot.empty() && object->path.compare(0, m_gameRoot.size(), m_gameRoot) == 0;
			FillGuestMemory(output, 0, 8); Write(output, 8u); Write(output + 4, static_cast<std::uint8_t>(optical));
			status = StatusSuccess; information = 8;
		} else if (object && ordinal == 196 && control == 0x00070024) {
			const bool readOnly = !m_gameRoot.empty() && object->path.compare(0, m_gameRoot.size(), m_gameRoot) == 0;
			status = readOnly ? StatusAccessDenied : StatusSuccess;
		} else if (object && ordinal == 196 && control == 0x0002404C && outputLength >= 24 && IsRangeValid(output, 24)) {
			LARGE_INTEGER size = {}; if (object->nativeHandle != INVALID_HANDLE_VALUE) GetFileSizeEx(object->nativeHandle, &size);
			FillGuestMemory(output, 0, 24); Write(output, static_cast<std::uint64_t>((std::max)(1ll, size.QuadPart / (2048ll * 32ll))));
			Write(output + 8, 32u); Write(output + 12, 1u); Write(output + 16, 11u); Write(output + 20, 2048u);
			status = StatusSuccess; information = 24;
		} else if (object && ordinal == 196 && control == 0x00024000 && outputLength >= 20 && IsRangeValid(output, 20)) {
			FillGuestMemory(output, 0, 20); Write(output + 1, static_cast<std::uint8_t>(18)); Write(output + 2, static_cast<std::uint8_t>(1)); Write(output + 3, static_cast<std::uint8_t>(1));
			Write(output + 5, static_cast<std::uint8_t>(0x14)); Write(output + 6, static_cast<std::uint8_t>(1)); Write(output + 10, static_cast<std::uint8_t>(2));
			Write(output + 13, static_cast<std::uint8_t>(0x14)); Write(output + 14, static_cast<std::uint8_t>(0xAA));
			status = StatusSuccess; information = 20;
		} else if (object && ordinal == 196 && control == 0x4D014 && inputLength >= 24 && IsRangeValid(input, inputLength)) {
			std::uint32_t dataBuffer = 0; Read(input + 20, dataBuffer);
			if (IsRangeValid(dataBuffer, 16)) { Write(dataBuffer + 10, static_cast<std::uint8_t>(1)); Write(dataBuffer + 11, static_cast<std::uint8_t>(1)); Write(dataBuffer + 12, static_cast<std::uint8_t>(1)); status = StatusSuccess; }
		} else if (object && ordinal == 200 && (control == 0x00090018 || control == 0x0009001C ||
			control == 0x00090020 || control == 0x00090028 || control == 0x00090030 || control == 0x0009C040)) {
			status = StatusSuccess;
		} else if (object && ordinal == 200 && control == 0x0009003C && outputLength >= 2 && IsRangeValid(output, 2)) {
			Write(output, static_cast<std::uint16_t>(0)); status = StatusSuccess; information = 2;
		} else if (object && ordinal == 200 && (control == 0x0009411C || control == 0x00098120) && inputLength >= 12 && IsRangeValid(input, 12)) {
			std::uint32_t offset = 0, length = 0, buffer = 0; Read(input, offset); Read(input + 4, length); Read(input + 8, buffer);
			if (object->nativeHandle != INVALID_HANDLE_VALUE && IsRangeValid(buffer, length)) { LARGE_INTEGER move = {}; move.QuadPart = offset; DWORD done = 0;
				if (SetFilePointerEx(object->nativeHandle, move, nullptr, FILE_BEGIN) && (control == 0x0009411C ? ReadFile(object->nativeHandle, GuestPointer(buffer, length), length, &done, nullptr) : WriteFile(object->nativeHandle, GuestPointer(buffer, length), length, &done, nullptr))) { status = StatusSuccess; information = done; } }
		}
		if (object && status == StatusInvalidDeviceRequest) LogUnknownControl(ordinal == 196, control, input, inputLength, outputLength, object);
		WriteIoStatus(iosb, status, information);
		SignalFileCompletion(object, status);
		if (completionEvent) { completionEvent->signaled = true; SyncDispatcherSignal(completionEvent); m_objectChanged.notify_all(); }
		if (apcRoutine && IsRangeValid(apcRoutine, 1) && !m_threads.empty()) { auto& thread = m_threads[m_currentThreadIndex]; thread.apcs.push_back({ 0, 0, 0, apcRoutine, apcContext, iosb, 0, true }); Write(thread.guestThread + 0x4A, static_cast<std::uint8_t>(1)); }
		WakeThreads(); SyncReadyList();
		m_regs->eax = status; FinishStdcall(10); break;
	}
	case 197: { // NtDuplicateObject
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c)) return Unsupported(ordinal); auto object = GetHandle(a);
		if (!object) m_regs->eax = StatusInvalidHandle;
		else {
			m_regs->eax = CreateOutputHandle(object, b);
			if (m_regs->eax == StatusSuccess && (c & 1u)) CloseGuestHandle(a);
		}
		FinishStdcall(3); break;
	}
	case 198: { // NtFlushBuffersFile
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(b, 8)) return Unsupported(ordinal); auto object = GetHandle(a);
		const auto status = object && (object->xiso || object->brokeredOptical) ? StatusSuccess :
			(object && object->nativeHandle != INVALID_HANDLE_VALUE && FlushFileBuffers(object->nativeHandle) ? StatusSuccess : StatusInvalidHandle);
		SignalFileCompletion(object, status);
		WriteIoStatus(b, status, 0); WakeThreads(); SyncReadyList(); m_regs->eax = status; FinishStdcall(2); break;
	}
	case 199: { // NtFreeVirtualMemory
		std::uint32_t freeType = 0, base = 0, size = 0;
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, freeType) || !IsRangeValid(a, 4) || !IsRangeValid(b, 4)) return Unsupported(ordinal);
		Read(a, base); Read(b, size); std::uint32_t allocationBase = 0, allocationSize = 0;
		if ((freeType != XboxMemRelease && freeType != XboxMemDecommit) || !FindAllocation(base, allocationBase, allocationSize)) m_regs->eax = StatusMemoryNotAllocated;
		else if (freeType == XboxMemRelease) {
			if (size != 0 || base != allocationBase) m_regs->eax = StatusInvalidParameter;
			else { Free(allocationBase); Write(a, 0u); Write(b, 0u); m_regs->eax = StatusSuccess; }
		} else {
			const std::uint32_t alignedBase = base & ~0xFFFu;
			const std::uint32_t span = size ? ((size + (base - alignedBase) + 0xFFFu) & ~0xFFFu) : allocationSize - (alignedBase - allocationBase);
			if (!span || static_cast<std::uint64_t>(alignedBase) + span > static_cast<std::uint64_t>(allocationBase) + allocationSize) m_regs->eax = StatusInvalidParameter;
			else { std::lock_guard<std::mutex> lock(m_memoryMutex); SetPageRange(alignedBase, span, XboxMemReserve, PAGE_NOACCESS); FillGuestMemory(alignedBase, 0, span); Write(a, alignedBase); Write(b, span); m_regs->eax = StatusSuccess; }
		}
		FinishStdcall(3); break;
	}
	case 202: { // NtOpenFile
		std::uint32_t access = 0, attrs = 0, iosb = 0, share = 0, options = 0;
		if (!ReadStack(0, a) || !ReadStack(1, access) || !ReadStack(2, attrs) || !ReadStack(3, iosb) || !ReadStack(4, share) || !ReadStack(5, options)) return Unsupported(ordinal);
		const std::uint32_t openStatus = OpenGuestFile(a, access, attrs, iosb, share, 1, options);
		if (m_logger) {
			std::wstring guestName; std::uint32_t rootHandle = 0;
			ReadObjectName(attrs, guestName, rootHandle);
			std::string printable;
			printable.reserve(guestName.size());
			for (const wchar_t character : guestName)
				printable.push_back(character >= 0x20 && character <= 0x7E ? static_cast<char>(character) : '?');
			char line[512] = {};
			sprintf_s(line, "[uwp-file] NtOpenFile status=0x%08X root=0x%08X options=0x%08X path=\"%s\".\r\n",
				openStatus, rootHandle, options, printable.c_str());
			m_logger(line);
		}
		m_regs->eax = openStatus; FinishStdcall(6); break;
	}
	case 203: { // NtOpenSymbolicLinkObject
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 4)) return Unsupported(ordinal); Write(a, 0u); std::wstring name; const std::uint32_t resolveStatus = ResolveObjectName(b, name); if (resolveStatus != StatusSuccess) m_regs->eax = resolveStatus; else { auto found = m_namedObjects.find(NormalizeObjectName(name)); if (found == m_namedObjects.end()) m_regs->eax = StatusObjectNameNotFound; else if (found->second->kind != ObjectKind::SymbolicLink) m_regs->eax = 0xC0000024u; else m_regs->eax = CreateOutputHandle(found->second, a); } FinishStdcall(2); break;
	}
	case 204: { // NtProtectVirtualMemory
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !ReadStack(3, d) || !IsRangeValid(a, 4) || !IsRangeValid(b, 4) || (d && !IsRangeValid(d, 4))) return Unsupported(ordinal);
		std::uint32_t base = 0, size = 0; Read(a, base); Read(b, size); const std::uint32_t alignedBase = base & ~0xFFFu;
		const std::uint32_t span = size ? ((size + (base - alignedBase) + 0xFFFu) & ~0xFFFu) : 0;
		std::uint32_t allocationBase = 0, allocationSize = 0, old = PAGE_NOACCESS; bool committed = span != 0 && FindAllocation(alignedBase, allocationBase, allocationSize) && static_cast<std::uint64_t>(alignedBase) + span <= static_cast<std::uint64_t>(allocationBase) + allocationSize;
		if (committed) { std::lock_guard<std::mutex> lock(m_memoryMutex); for (std::uint32_t page = alignedBase; page < alignedBase + span; page += 0x1000) { auto state = m_pageState.find(page); if (state == m_pageState.end() || state->second != XboxMemCommit) { committed = false; break; } if (page == alignedBase) { auto protection = m_pageProtect.find(page); if (protection != m_pageProtect.end()) old = protection->second; } } if (committed) SetPageRange(alignedBase, span, XboxMemCommit, c); }
		if (!committed) m_regs->eax = StatusMemoryNotAllocated; else { Write(a, alignedBase); Write(b, span); if (d) Write(d, old); m_regs->eax = StatusSuccess; }
		FinishStdcall(4); break;
	}
	case 205: { // NtPulseEvent (ordinal collision in legacy headers resolves to pulse)
		if (!ReadStack(0, a) || !ReadStack(1, b) || (b && !IsRangeValid(b, 4))) return Unsupported(ordinal); auto object = GetHandle(a);
		if (!object) m_regs->eax = StatusInvalidHandle;
		else if (object->kind != ObjectKind::Event) m_regs->eax = 0xC0000024u;
		else { c = PulseEventObject(object); if (b) Write(b, c); m_regs->eax = StatusSuccess; }
		FinishStdcall(2); break;
	}
	case 206: { // NtQueueApcThread
		std::uint32_t routine = 0, context = 0, argument1 = 0, argument2 = 0;
		if (!ReadStack(0, a) || !ReadStack(1, routine) || !ReadStack(2, context) || !ReadStack(3, argument1) || !ReadStack(4, argument2)) return Unsupported(ordinal);
		auto* thread = FindThreadByHandle(a);
		if (!thread || !routine || !IsRangeValid(routine, 1)) m_regs->eax = StatusInvalidHandle;
		else { thread->apcs.push_back({ 0, 0, 0, routine, context, argument1, argument2, true }); Write(thread->guestThread + 0x4A, static_cast<std::uint8_t>(1)); m_regs->eax = StatusSuccess; }
		FinishStdcall(5); break;
	}
	case 207: { // NtQueryDirectoryFile
		std::uint32_t eventHandle = 0, apcRoutine = 0, apcContext = 0, iosb = 0;
		std::uint32_t buffer = 0, length = 0, infoClass = 0, maskAddress = 0, restart = 0;
		if (!ReadStack(0, a) || !ReadStack(1, eventHandle) || !ReadStack(2, apcRoutine) ||
			!ReadStack(3, apcContext) || !ReadStack(4, iosb) || !ReadStack(5, buffer) ||
			!ReadStack(6, length) || !ReadStack(7, infoClass) || !ReadStack(8, maskAddress) ||
			!ReadStack(9, restart) || !IsRangeValid(iosb, 8)) return Unsupported(ordinal);
		ObjectPtr completionEvent;
		if (eventHandle) completionEvent = GetHandle(eventHandle);
		if ((eventHandle && (!completionEvent || completionEvent->kind != ObjectKind::Event)) ||
			(apcRoutine && !IsRangeValid(apcRoutine, 1))) {
			const std::uint32_t failure = eventHandle && (!completionEvent || completionEvent->kind != ObjectKind::Event) ?
				StatusInvalidHandle : StatusInvalidParameter;
			WriteIoStatus(iosb, failure, 0); m_regs->eax = failure; FinishStdcall(10); break;
		}
		auto object = GetHandle(a); std::uint32_t status = StatusInvalidHandle, used = 0, previousEntry = 0;
		if (object && object->kind == ObjectKind::Directory) {
			if (infoClass != 1 || length < 64 || !IsRangeValid(buffer, length)) status = StatusInvalidParameter;
			else {
				std::wstring mask = L"*";
				if (maskAddress) {
					std::uint16_t maskLength = 0; std::uint32_t maskBuffer = 0;
					if (!Read(maskAddress, maskLength) || !Read(maskAddress + 4, maskBuffer) || !IsRangeValid(maskBuffer, maskLength)) status = StatusInvalidParameter;
					else { mask.clear(); for (std::uint32_t i = 0; i < maskLength; ++i) { std::uint8_t character = 0; Read(maskBuffer + i, character); mask.push_back(static_cast<wchar_t>(character)); } if (mask == L"*.*") mask = L"*"; }
				}
				if (status != StatusInvalidParameter && (restart || object->findMask != mask ||
					(object->xiso ? object->xisoDirectory.empty() : object->hostDirectory.empty()))) {
					object->findMask = mask; object->count = 0; object->xisoDirectory.clear(); object->hostDirectory.clear();
					if (object->xiso) {
						if (FAILED(m_xiso->Enumerate(object->xisoEntry.path, object->xisoDirectory))) status = StatusObjectNameNotFound;
					} else {
						bool brokered = false;
						if (!m_gameRoot.empty() && object->path.size() >= m_gameRoot.size() &&
							_wcsnicmp(object->path.c_str(), m_gameRoot.c_str(), m_gameRoot.size()) == 0) {
							std::wstring relative = object->path.substr(m_gameRoot.size());
							while (!relative.empty() && (relative.front() == L'\\' || relative.front() == L'/')) relative.erase(relative.begin());
							brokered = SUCCEEDED(CxbxUwpEnumerateBrokeredGameDirectory(relative.c_str(), mask.c_str(), object->hostDirectory));
						}
						if (!brokered) {
							WIN32_FIND_DATAW data = {}; const std::wstring pattern = object->path + L"\\" + mask;
							HANDLE find = FindFirstFileExFromAppW(pattern.c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, 0);
							if (find != INVALID_HANDLE_VALUE) {
								do { if (wcscmp(data.cFileName, L".") && wcscmp(data.cFileName, L"..")) object->hostDirectory.push_back(data); } while (FindNextFileW(find, &data));
								FindClose(find);
							}
						}
					}
				}
				std::string narrowMask; for (const wchar_t ch : mask) narrowMask.push_back(ch <= 0xFF ? static_cast<char>(ch) : '?');
				auto appendEntry = [this, buffer, length, &used, &previousEntry](const std::string& name,
					std::uint64_t creation, std::uint64_t access, std::uint64_t write, std::uint64_t size, std::uint32_t attributes) {
					const std::uint32_t raw = 64 + static_cast<std::uint32_t>(name.size());
					const std::uint32_t aligned = (raw + 3u) & ~3u;
					if (aligned > length - used) return false;
					const std::uint32_t entry = buffer + used; FillGuestMemory(entry, 0, aligned);
					if (previousEntry) Write(previousEntry, entry - previousEntry);
					Write(entry + 8, creation); Write(entry + 16, access); Write(entry + 24, write); Write(entry + 32, write);
					Write(entry + 40, size); Write(entry + 48, size); Write(entry + 56, attributes);
					Write(entry + 60, static_cast<std::uint32_t>(name.size()));
					if (!name.empty()) std::memcpy(GuestPointer(entry + 64, name.size()), name.data(), name.size());
					previousEntry = entry; used += aligned; return true;
				};
				if (status != StatusInvalidParameter && status != StatusObjectNameNotFound) {
					if (object->xiso) {
						while (static_cast<std::size_t>(object->count) < object->xisoDirectory.size()) {
							const auto& entry = object->xisoDirectory[object->count];
							if (!MatchFileMask(entry.name, narrowMask)) { ++object->count; continue; }
							if (!appendEntry(entry.name, 0, 0, 0, entry.size, entry.attributes)) break;
							++object->count;
						}
					} else {
						while (static_cast<std::size_t>(object->count) < object->hostDirectory.size()) {
							const auto& entry = object->hostDirectory[object->count]; std::string name;
							for (const wchar_t* p = entry.cFileName; *p; ++p) name.push_back(static_cast<char>(*p <= 0xFF ? *p : '?'));
							const std::uint64_t creation = (static_cast<std::uint64_t>(entry.ftCreationTime.dwHighDateTime) << 32) | entry.ftCreationTime.dwLowDateTime;
							const std::uint64_t access = (static_cast<std::uint64_t>(entry.ftLastAccessTime.dwHighDateTime) << 32) | entry.ftLastAccessTime.dwLowDateTime;
							const std::uint64_t write = (static_cast<std::uint64_t>(entry.ftLastWriteTime.dwHighDateTime) << 32) | entry.ftLastWriteTime.dwLowDateTime;
							const std::uint64_t size = (static_cast<std::uint64_t>(entry.nFileSizeHigh) << 32) | entry.nFileSizeLow;
							if (!appendEntry(name, creation, access, write, size, entry.dwFileAttributes)) break;
							++object->count;
						}
					}
					const bool exhausted = object->xiso ? static_cast<std::size_t>(object->count) >= object->xisoDirectory.size() :
						static_cast<std::size_t>(object->count) >= object->hostDirectory.size();
					status = used ? StatusSuccess : exhausted ? StatusNoMoreFiles : StatusBufferTooSmall;
				}
			}
		}
		WriteIoStatus(iosb, status, used);
		SignalFileCompletion(object, status);
		if (completionEvent) { completionEvent->signaled = true; SyncDispatcherSignal(completionEvent); m_objectChanged.notify_all(); }
		if (apcRoutine && IsRangeValid(apcRoutine, 1) && !m_threads.empty()) { auto& thread = m_threads[m_currentThreadIndex]; thread.apcs.push_back({ 0, 0, 0, apcRoutine, apcContext, iosb, 0, true }); Write(thread.guestThread + 0x4A, static_cast<std::uint8_t>(1)); }
		WakeThreads(); SyncReadyList();
		m_regs->eax = status; FinishStdcall(10); break;
	}
	case 208: { // NtQueryDirectoryObject
		std::uint32_t buffer = 0, length = 0, restart = 0, context = 0, returned = 0;
		if (!ReadStack(0, a) || !ReadStack(1, buffer) || !ReadStack(2, length) ||
			!ReadStack(3, restart) || !ReadStack(4, context) || !ReadStack(5, returned) ||
			!IsRangeValid(context, 4)) return Unsupported(ordinal);
		auto directory = GetHandle(a);
		if (!directory || directory->kind != ObjectKind::Directory) m_regs->eax = StatusInvalidHandle;
		else {
			std::vector<std::pair<std::string, ObjectPtr>> children;
			const std::wstring root = NormalizeObjectName(directory->path);
			const std::wstring prefix = root.empty() || root == L"\\" ? L"\\" : root + L"\\";
			for (const auto& named : m_namedObjects) {
				if (named.second.get() == directory.get()) continue;
				const std::wstring key = named.first;
				if (key.size() <= prefix.size() || key.compare(0, prefix.size(), prefix) != 0) continue;
				const std::wstring suffix = key.substr(prefix.size());
				if (suffix.find(L'\\') != std::wstring::npos) continue;
				std::wstring original = named.second->path;
				const auto separator = original.find_last_of(L"\\/");
				if (separator != std::wstring::npos) original.erase(0, separator + 1);
				std::string name; for (const wchar_t character : original) name.push_back(character <= 0xFF ? static_cast<char>(character) : '?');
				children.emplace_back(std::move(name), named.second);
			}
			std::sort(children.begin(), children.end(), [](const auto& left, const auto& right) {
				return _stricmp(left.first.c_str(), right.first.c_str()) < 0;
			});
			std::uint32_t index = 0; if (!restart) Read(context, index);
			if (index >= children.size()) { if (returned) Write(returned, 0u); m_regs->eax = StatusNoMoreFiles; }
			else {
				const std::string& name = children[index].first;
				const ObjectKind kind = children[index].second->kind;
				const char* typeName = kind == ObjectKind::Directory ? "Directory" :
					kind == ObjectKind::SymbolicLink ? "SymbolicLink" : kind == ObjectKind::Event ? "Event" :
					kind == ObjectKind::Semaphore ? "Semaphore" : kind == ObjectKind::Mutant ? "Mutant" :
					kind == ObjectKind::Timer ? "Timer" : kind == ObjectKind::Thread ? "Thread" :
					kind == ObjectKind::IoCompletion ? "IoCompletion" : kind == ObjectKind::File ? "File" : "Queue";
				const std::string type(typeName);
				const std::uint32_t required = 16 + static_cast<std::uint32_t>(name.size() + type.size() + 2);
				if (length < required || !IsRangeValid(buffer, required)) m_regs->eax = StatusBufferTooSmall;
				else { FillGuestMemory(buffer, 0, required); Write(buffer, static_cast<std::uint16_t>(name.size())); Write(buffer + 2, static_cast<std::uint16_t>(name.size() + 1)); Write(buffer + 4, buffer + 16); Write(buffer + 8, static_cast<std::uint16_t>(type.size())); Write(buffer + 10, static_cast<std::uint16_t>(type.size() + 1)); Write(buffer + 12, buffer + 17 + static_cast<std::uint32_t>(name.size())); std::memcpy(GuestPointer(buffer + 16, name.size() + 1), name.c_str(), name.size() + 1); std::memcpy(GuestPointer(buffer + 17 + static_cast<std::uint32_t>(name.size()), type.size() + 1), type.c_str(), type.size() + 1); Write(context, index + 1); if (returned) Write(returned, required); m_regs->eax = StatusSuccess; }
			}
		}
		FinishStdcall(6); break;
	}
	case 209: { // NtQueryEvent
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(b, 8)) return Unsupported(ordinal); auto object = GetHandle(a);
		if (!object) m_regs->eax = StatusInvalidHandle;
		else if (object->kind != ObjectKind::Event) m_regs->eax = 0xC0000024u;
		else { Write(b, object->manualReset ? 0u : 1u); Write(b + 4, object->signaled ? 1u : 0u); m_regs->eax = StatusSuccess; }
		FinishStdcall(2); break;
	}
	case 210: { // NtQueryFullAttributesFile
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal); std::wstring path;
		if (!ResolveGuestPath(a, path) || !IsRangeValid(b, 56)) { m_regs->eax = StatusInvalidParameter; FinishStdcall(2); break; }
		std::string xisoPath;
		if (GetXisoRelativePath(path, xisoPath)) {
			CxbxUwpXisoEntry entry; const HRESULT result = m_xiso->Find(xisoPath, entry);
			if (FAILED(result)) m_regs->eax = StatusFromWin32(HRESULT_CODE(result));
			else { FillGuestMemory(b, 0, 56); Write(b + 32, static_cast<std::uint64_t>(entry.size)); Write(b + 40, static_cast<std::uint64_t>(entry.size)); Write(b + 48, static_cast<std::uint32_t>(entry.attributes)); m_regs->eax = StatusSuccess; }
			FinishStdcall(2); break;
		}
		CREATEFILE2_EXTENDED_PARAMETERS p = { sizeof(p) }; p.dwFileAttributes = FILE_ATTRIBUTE_NORMAL; p.dwFileFlags = FILE_FLAG_BACKUP_SEMANTICS;
		HANDLE file = CreateFile2FromAppW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING, &p);
		if (file == INVALID_HANDLE_VALUE && !m_gameRoot.empty() && path.size() >= m_gameRoot.size() &&
			_wcsnicmp(path.c_str(), m_gameRoot.c_str(), m_gameRoot.size()) == 0) {
			std::wstring relative = path.substr(m_gameRoot.size());
			while (!relative.empty() && (relative.front() == L'\\' || relative.front() == L'/')) relative.erase(relative.begin());
			const HRESULT brokerResult = CxbxUwpOpenBrokeredGameFile(relative.c_str(), relative.empty(),
				GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 1, 0, &file);
			if (FAILED(brokerResult)) SetLastError(HRESULT_FACILITY(brokerResult) == FACILITY_WIN32 ? HRESULT_CODE(brokerResult) : ERROR_ACCESS_DENIED);
		}
		if (file == INVALID_HANDLE_VALUE && path.size() == m_gameRoot.size() &&
			!m_gameRoot.empty() && _wcsicmp(path.c_str(), m_gameRoot.c_str()) == 0) {
			FillGuestMemory(b, 0, 56);
			Write(b + 48, static_cast<std::uint32_t>(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY));
			m_regs->eax = StatusSuccess;
		}
		else if (file == INVALID_HANDLE_VALUE) m_regs->eax = StatusFromWin32(GetLastError());
		else { BY_HANDLE_FILE_INFORMATION info = {}; LARGE_INTEGER size = {}; GetFileInformationByHandle(file, &info); GetFileSizeEx(file, &size); CloseHandle(file);
			FillGuestMemory(b, 0, 56); const std::uint64_t creation = (static_cast<std::uint64_t>(info.ftCreationTime.dwHighDateTime) << 32) | info.ftCreationTime.dwLowDateTime;
			const std::uint64_t access = (static_cast<std::uint64_t>(info.ftLastAccessTime.dwHighDateTime) << 32) | info.ftLastAccessTime.dwLowDateTime;
			const std::uint64_t write = (static_cast<std::uint64_t>(info.ftLastWriteTime.dwHighDateTime) << 32) | info.ftLastWriteTime.dwLowDateTime;
			Write(b, creation); Write(b + 8, access); Write(b + 16, write); Write(b + 24, write); Write(b + 32, static_cast<std::uint64_t>(size.QuadPart)); Write(b + 40, static_cast<std::uint64_t>(size.QuadPart)); Write(b + 48, info.dwFileAttributes); m_regs->eax = StatusSuccess; }
		FinishStdcall(2); break;
	}
	case 211: { // NtQueryInformationFile
		std::uint32_t iosb = 0, buffer = 0, length = 0, infoClass = 0;
		if (!ReadStack(0, a) || !ReadStack(1, iosb) || !ReadStack(2, buffer) || !ReadStack(3, length) ||
			!ReadStack(4, infoClass) || !IsRangeValid(iosb, 8)) return Unsupported(ordinal);
		auto object = GetHandle(a); std::uint32_t status = StatusInvalidHandle, used = 0;
		if (object && (object->xiso || object->brokeredOptical || object->nativeHandle != INVALID_HANDLE_VALUE)) {
			std::uint64_t creation = 0, access = 0, write = 0, size = 0, position = object->xisoPosition;
			std::uint32_t attributes = object->xiso ? object->xisoEntry.attributes : FILE_ATTRIBUTE_NORMAL;
			std::uint32_t links = 1;
			if (object->xiso) size = object->xisoVolume ? m_xiso->ImageSize() : object->xisoEntry.size;
			else if (object->nativeHandle != INVALID_HANDLE_VALUE) {
				LARGE_INTEGER nativeSize = {}, nativePosition = {}; BY_HANDLE_FILE_INFORMATION nativeInfo = {};
				GetFileSizeEx(object->nativeHandle, &nativeSize); GetFileInformationByHandle(object->nativeHandle, &nativeInfo);
				SetFilePointerEx(object->nativeHandle, {}, &nativePosition, FILE_CURRENT);
				size = object->rawDevice ? XboxPartitionBytes(object->partitionNumber) : static_cast<std::uint64_t>(nativeSize.QuadPart);
				position = nativePosition.QuadPart; attributes = nativeInfo.dwFileAttributes;
				links = nativeInfo.nNumberOfLinks;
				creation = (static_cast<std::uint64_t>(nativeInfo.ftCreationTime.dwHighDateTime) << 32) | nativeInfo.ftCreationTime.dwLowDateTime;
				access = (static_cast<std::uint64_t>(nativeInfo.ftLastAccessTime.dwHighDateTime) << 32) | nativeInfo.ftLastAccessTime.dwLowDateTime;
				write = (static_cast<std::uint64_t>(nativeInfo.ftLastWriteTime.dwHighDateTime) << 32) | nativeInfo.ftLastWriteTime.dwLowDateTime;
			}
			else attributes = object->kind == ObjectKind::Directory ?
				(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY) : FILE_ATTRIBUTE_READONLY;
			std::wstring leaf = object->path; const auto slash = leaf.find_last_of(L"\\/"); if (slash != std::wstring::npos) leaf.erase(0, slash + 1);
			std::string name; for (const wchar_t ch : leaf) name.push_back(ch <= 0xFF ? static_cast<char>(ch) : '?');
			auto require = [this, buffer, length, &status, &used](std::uint32_t bytes) {
				if (length < bytes || !IsRangeValid(buffer, bytes)) { status = StatusBufferTooSmall; return false; }
				FillGuestMemory(buffer, 0, bytes); used = bytes; status = StatusSuccess; return true;
			};
			auto writeBasic = [this, buffer, creation, access, write, attributes](std::uint32_t offset) {
				Write(buffer + offset, creation); Write(buffer + offset + 8, access); Write(buffer + offset + 16, write);
				Write(buffer + offset + 24, write); Write(buffer + offset + 32, attributes);
			};
			auto writeStandard = [this, buffer, size, links, object](std::uint32_t offset) {
				Write(buffer + offset, (size + 4095ull) & ~4095ull); Write(buffer + offset + 8, size);
				Write(buffer + offset + 16, links); Write(buffer + offset + 20, static_cast<std::uint8_t>(object->deleteOnClose));
				Write(buffer + offset + 21, static_cast<std::uint8_t>(object->kind == ObjectKind::Directory));
			};
			switch (infoClass) {
			case 4: if (require(40)) writeBasic(0); break; // FileBasicInformation
			case 5: if (require(24)) writeStandard(0); break;
			case 6: if (require(8)) Write(buffer, static_cast<std::uint64_t>(std::hash<std::wstring>{}(object->path))); break;
			case 7: if (require(4)) Write(buffer, 0u); break;
			case 8: if (require(4)) Write(buffer, object->desiredAccess); break;
			case 9: { const std::uint32_t required = 4 + static_cast<std::uint32_t>(name.size()); if (require(required)) { Write(buffer, static_cast<std::uint32_t>(name.size())); if (!name.empty()) std::memcpy(GuestPointer(buffer + 4, name.size()), name.data(), name.size()); } break; }
			case 14: if (require(8)) Write(buffer, position); break;
			case 16: if (require(4)) Write(buffer, object->openOptions); break;
			case 17: if (require(4)) Write(buffer, 0u); break;
			case 18: { const std::uint32_t required = 100 + static_cast<std::uint32_t>(name.size()); if (require(required)) { writeBasic(0); writeStandard(40); Write(buffer + 64, static_cast<std::uint64_t>(std::hash<std::wstring>{}(object->path))); Write(buffer + 72, 0u); Write(buffer + 76, object->desiredAccess); Write(buffer + 80, position); Write(buffer + 88, object->openOptions); Write(buffer + 92, 0u); Write(buffer + 96, static_cast<std::uint32_t>(name.size())); if (!name.empty()) std::memcpy(GuestPointer(buffer + 100, name.size()), name.data(), name.size()); } break; }
			case 28: if (require(16)) { Write(buffer, size); Write(buffer + 8, static_cast<std::uint16_t>(0)); } break;
			case 34: if (require(56)) { writeBasic(0); Write(buffer + 32, (size + 4095ull) & ~4095ull); Write(buffer + 40, size); Write(buffer + 48, attributes); } break;
			case 35: if (require(8)) { Write(buffer, attributes); Write(buffer + 4, 0u); } break;
			default: status = 0xC0000003u; used = 0; break;
			}
		}
		WriteIoStatus(iosb, status, used); SignalFileCompletion(object, status);
		WakeThreads(); SyncReadyList(); m_regs->eax = status; FinishStdcall(5); break;
	}
	case 212: { // NtQueryIoCompletion
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(b, 4)) return Unsupported(ordinal); auto object = GetHandle(a); if (!object) m_regs->eax = StatusInvalidHandle; else if (object->kind != ObjectKind::IoCompletion) m_regs->eax = 0xC0000024u; else { Write(b, static_cast<std::uint32_t>(object->completions.size())); m_regs->eax = StatusSuccess; } FinishStdcall(2); break;
	}
	case 213: { // NtQueryMutant
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(b, 8)) return Unsupported(ordinal); auto object = GetHandle(a);
		if (!object) m_regs->eax = StatusInvalidHandle;
		else if (object->kind != ObjectKind::Mutant) m_regs->eax = 0xC0000024u;
		else {
			Write(b, static_cast<std::int32_t>(object->signaled ? 1 : 1 - static_cast<std::int32_t>(object->recursionCount)));
			Write(b + 4, static_cast<std::uint8_t>(object->ownerThreadId == m_threads[m_currentThreadIndex].id));
			Write(b + 5, static_cast<std::uint8_t>(object->abandoned));
			Write(b + 6, static_cast<std::uint16_t>(0));
			m_regs->eax = StatusSuccess;
		} FinishStdcall(2); break;
	}
	case 214: { // NtQuerySemaphore
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(b, 8)) return Unsupported(ordinal); auto object = GetHandle(a);
		if (!object) m_regs->eax = StatusInvalidHandle;
		else if (object->kind != ObjectKind::Semaphore) m_regs->eax = 0xC0000024u;
		else { Write(b, static_cast<std::uint32_t>(object->count)); Write(b + 4, static_cast<std::uint32_t>(object->limit)); m_regs->eax = StatusSuccess; } FinishStdcall(2); break;
	}
	case 215: { // NtQuerySymbolicLinkObject
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(b, 8) || (c && !IsRangeValid(c, 4))) return Unsupported(ordinal); auto object = GetHandle(a); if (!object) m_regs->eax = StatusInvalidHandle; else if (object->kind != ObjectKind::SymbolicLink) m_regs->eax = 0xC0000024u; else { std::uint16_t maximum = 0; std::uint32_t buffer = 0; Read(b + 2, maximum); Read(b + 4, buffer); const std::uint32_t required = static_cast<std::uint32_t>(object->target.size()); if (c) Write(c, required + 1u); if (maximum < required || !IsRangeValid(buffer, required)) m_regs->eax = StatusBufferTooSmall; else { for (std::uint32_t i = 0; i < required; ++i) Write(buffer + i, static_cast<std::uint8_t>(object->target[i] & 0xFF)); Write(b, static_cast<std::uint16_t>(required)); m_regs->eax = StatusSuccess; } } FinishStdcall(3); break;
	}
	case 216: { // NtQueryTimer
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(b, 12)) return Unsupported(ordinal); auto object = GetHandle(a);
		if (!object) m_regs->eax = StatusInvalidHandle;
		else if (object->kind != ObjectKind::Timer) m_regs->eax = 0xC0000024u;
		else { std::int64_t remaining = 0; if (object->timerActive) remaining = -std::chrono::duration_cast<std::chrono::nanoseconds>((std::max)(object->due, std::chrono::steady_clock::now()) - std::chrono::steady_clock::now()).count() / 100; Write(b, remaining); Write(b + 8, object->signaled ? 1u : 0u); m_regs->eax = StatusSuccess; } FinishStdcall(2); break;
	}
	case 217: { // NtQueryVirtualMemory
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(b, 28)) return Unsupported(ordinal);
		const std::uint32_t page = a & ~0xFFFu; std::uint32_t allocationBase = 0, allocationSize = 0;
		bool queryValid = true;
		if (FindAllocation(page, allocationBase, allocationSize)) {
			std::lock_guard<std::mutex> lock(m_memoryMutex);
			const auto stateIt = m_pageState.find(page);
			const std::uint32_t state = stateIt == m_pageState.end() ? 0x10000u : stateIt->second;
			const auto protectIt = m_pageProtect.find(page);
			const std::uint32_t protect = state == XboxMemCommit && protectIt != m_pageProtect.end() ? protectIt->second : PAGE_NOACCESS;
			std::uint32_t regionSize = 0x1000;
			while (page + regionSize < allocationBase + allocationSize) {
				const std::uint32_t next = page + regionSize;
				const auto nextState = m_pageState.find(next); const auto nextProtect = m_pageProtect.find(next);
				if ((nextState == m_pageState.end() ? 0x10000u : nextState->second) != state ||
					(state == XboxMemCommit && (nextProtect == m_pageProtect.end() ? PAGE_NOACCESS : nextProtect->second) != protect)) break;
				regionSize += 0x1000;
			}
			Write(b, page); Write(b + 4, allocationBase);
			Write(b + 8, m_allocationProtect.count(allocationBase) ? m_allocationProtect[allocationBase] : PAGE_NOACCESS);
			Write(b + 12, regionSize); Write(b + 16, state); Write(b + 20, protect); Write(b + 24, 0x20000u);
		} else if (page < m_imageEndAddress) {
			const std::uint32_t imageEnd = (m_imageEndAddress + 0xFFFu) & ~0xFFFu;
			Write(b, page); Write(b + 4, 0x00010000u); Write(b + 8, static_cast<std::uint32_t>(PAGE_EXECUTE_READ));
			Write(b + 12, (std::max)(0x1000u, imageEnd - page)); Write(b + 16, XboxMemCommit);
			Write(b + 20, static_cast<std::uint32_t>(PAGE_EXECUTE_READ)); Write(b + 24, 0x01000000u);
		} else if (page >= 0x80000000u && IsRangeValid(page, 1)) {
			Write(b, page); Write(b + 4, 0x80000000u); Write(b + 8, static_cast<std::uint32_t>(PAGE_EXECUTE_READWRITE));
			Write(b + 12, 0x1000u); Write(b + 16, XboxMemCommit);
			Write(b + 20, static_cast<std::uint32_t>(PAGE_EXECUTE_READWRITE)); Write(b + 24, 0x01000000u);
		} else if (page < 0x80000000u) {
			std::uint32_t nextBase = 0x80000000u;
			for (const auto& allocation : m_allocations)
				if (allocation.first > page) nextBase = (std::min)(nextBase, allocation.first);
			const std::uint32_t regionEnd = (std::max)(page + 0x1000u, nextBase);
			Write(b, page); Write(b + 4, 0u); Write(b + 8, 0u); Write(b + 12, regionEnd - page);
			Write(b + 16, 0x10000u); Write(b + 20, 0u); Write(b + 24, 0u);
		} else queryValid = false;
		m_regs->eax = queryValid ? StatusSuccess : StatusMemoryNotAllocated;
		FinishStdcall(2); break;
	}
	case 218: { // NtQueryVolumeInformationFile
		std::uint32_t iosb = 0, info = 0, length = 0, infoClass = 0;
		if (!ReadStack(0, a) || !ReadStack(1, iosb) || !ReadStack(2, info) || !ReadStack(3, length) ||
			!ReadStack(4, infoClass) || !IsRangeValid(iosb, 8)) return Unsupported(ordinal);
		auto object = GetHandle(a); std::uint32_t status = object ? StatusSuccess : StatusInvalidHandle, used = 0;
		const bool optical = object && (object->xiso || (!m_gameRoot.empty() && object->path.size() >= m_gameRoot.size() && _wcsnicmp(object->path.c_str(), m_gameRoot.c_str(), m_gameRoot.size()) == 0));
		const std::uint64_t allocationUnits = object && object->rawDevice ?
			XboxPartitionLbaSize[object->partitionNumber] / 32ull : 0x01000000ull;
		auto require = [this, info, length, &status, &used](std::uint32_t bytes) {
			if (length < bytes || !IsRangeValid(info, bytes)) { status = StatusBufferTooSmall; return false; }
			FillGuestMemory(info, 0, bytes); used = bytes; return true;
		};
		if (status == StatusSuccess) switch (infoClass) {
		case 1: { // FileFsVolumeInformation
			const std::string label = optical ? "DVD" : "XBOX"; const std::uint32_t required = 17 + static_cast<std::uint32_t>(label.size());
			if (require(required)) { Write(info + 8, m_titleId ? m_titleId : 0x58424F58u); Write(info + 12, static_cast<std::uint32_t>(label.size())); Write(info + 16, static_cast<std::uint8_t>(0)); std::memcpy(GuestPointer(info + 17, label.size()), label.data(), label.size()); }
			break;
		}
		case 3: if (require(24)) { // FileFsSizeInformation
			// Retail FATX partitions normally use 32 sectors per allocation unit
			// (32 * 512 = 0x4000 bytes). Several titles reject the volume with
			// STATUS_WRONG_VOLUME when a host-filesystem cluster size is exposed.
			Write(info, optical ? 0x00040000ull : allocationUnits);
			Write(info + 8, optical ? 0ull : allocationUnits);
			Write(info + 16, optical ? 1u : 32u);
			Write(info + 20, optical ? 2048u : 512u);
		} break;
		case 4: if (require(8)) { Write(info, optical ? 2u : 7u); Write(info + 4, optical ? 1u : 0u); } break;
		case 5: { // FileFsAttributeInformation
			const std::string fs = optical ? "CDFS" : "FATX"; const std::uint32_t required = 12 + static_cast<std::uint32_t>(fs.size());
			if (require(required)) { Write(info, optical ? 1u : 0u); Write(info + 4, 42u); Write(info + 8, static_cast<std::uint32_t>(fs.size())); std::memcpy(GuestPointer(info + 12, fs.size()), fs.data(), fs.size()); }
			break;
		}
		case 7: if (require(32)) { // FileFsFullSizeInformation
			Write(info, optical ? 0x00040000ull : allocationUnits);
			Write(info + 8, optical ? 0ull : allocationUnits);
			Write(info + 16, optical ? 0ull : allocationUnits);
			Write(info + 24, optical ? 1u : 32u);
			Write(info + 28, optical ? 2048u : 512u);
		} break;
		default: status = 0xC0000003u; used = 0; break;
		}
		WriteIoStatus(iosb, status, used); SignalFileCompletion(object, status);
		WakeThreads(); SyncReadyList(); m_regs->eax = status; FinishStdcall(5); break;
	}
	case 219: case 236: { // NtReadFile / NtWriteFile
		std::uint32_t eventHandle = 0, apcRoutine = 0, apcContext = 0, iosb = 0, buffer = 0, length = 0, offsetAddress = 0;
		if (!ReadStack(0, a) || !ReadStack(1, eventHandle) || !ReadStack(2, apcRoutine) || !ReadStack(3, apcContext) || !ReadStack(4, iosb) || !ReadStack(5, buffer) || !ReadStack(6, length) || !ReadStack(7, offsetAddress) || !IsRangeValid(iosb, 8) || !IsRangeValid(buffer, length)) return Unsupported(ordinal);
		ObjectPtr completionEvent;
		if (eventHandle) completionEvent = GetHandle(eventHandle);
		if ((eventHandle && (!completionEvent || completionEvent->kind != ObjectKind::Event)) ||
			(apcRoutine && !IsRangeValid(apcRoutine, 1))) {
			const std::uint32_t failure = eventHandle && (!completionEvent || completionEvent->kind != ObjectKind::Event) ?
				StatusInvalidHandle : StatusInvalidParameter;
			WriteIoStatus(iosb, failure, 0); m_regs->eax = failure; FinishStdcall(8); break;
		}
		auto object = GetHandle(a); std::uint32_t status = StatusInvalidHandle; DWORD transferred = 0;
		if (object && object->guestAddress) { object->signaled = false; SyncDispatcherSignal(object); }
		if (object && object->kind == ObjectKind::File && object->xiso) {
			if (ordinal == 236) status = StatusAccessDenied;
			else { std::uint64_t offset = object->xisoPosition; if (offsetAddress) { std::int64_t requested = 0; if (!Read(offsetAddress, requested) || requested < 0) status = StatusInvalidParameter; else { offset = requested; status = StatusSuccess; } } else status = StatusSuccess;
				if (status == StatusSuccess) { std::uint32_t done = 0; const HRESULT result = object->xisoVolume ?
					m_xiso->ReadImage(offset, GuestPointer(buffer, length), length, done) :
					m_xiso->Read(object->xisoEntry, offset, GuestPointer(buffer, length), length, done);
					status = SUCCEEDED(result) ? StatusSuccess : StatusFromWin32(HRESULT_CODE(result)); transferred = done; object->xisoPosition = offset + done; } }
		}
		else if (object && object->kind == ObjectKind::File && object->nativeHandle != INVALID_HANDLE_VALUE) {
			if (offsetAddress) { std::int64_t offset = 0; if (!Read(offsetAddress, offset)) status = StatusInvalidParameter; else { LARGE_INTEGER move = {}; move.QuadPart = offset; if (!SetFilePointerEx(object->nativeHandle, move, nullptr, FILE_BEGIN)) status = StatusFromWin32(GetLastError()); else status = StatusSuccess; } } else status = StatusSuccess;
			if (status == StatusSuccess) {
				const BOOL ok = ordinal == 219 ? ReadFile(object->nativeHandle, GuestPointer(buffer, length), length, &transferred, nullptr) : WriteFile(object->nativeHandle, GuestPointer(buffer, length), length, &transferred, nullptr);
				status = ok ? StatusSuccess : StatusFromWin32(GetLastError());
				if (ok && ordinal == 219 && object->rawDevice && transferred < length) {
					// Unallocated sectors of a physical disk read as zero, not EOF.
					FillGuestMemory(buffer + transferred, 0, length - transferred);
					LARGE_INTEGER skip = {}; skip.QuadPart = length - transferred;
					if (!SetFilePointerEx(object->nativeHandle, skip, nullptr, FILE_CURRENT)) status = StatusFromWin32(GetLastError());
					else transferred = length;
				}
			}
		}
		if (object && object->guestAddress) {
			std::uint64_t position = object->xisoPosition;
			if (!object->xiso && object->nativeHandle != INVALID_HANDLE_VALUE) { LARGE_INTEGER zero = {}, current = {}; if (SetFilePointerEx(object->nativeHandle, zero, &current, FILE_CURRENT)) position = current.QuadPart; }
			Write(object->guestAddress + 0x14, position);
		}
		WriteIoStatus(iosb, status, transferred);
		SignalFileCompletion(object, status);
		if (completionEvent) { completionEvent->signaled = true; SyncDispatcherSignal(completionEvent); m_objectChanged.notify_all(); }
		if (apcRoutine && IsRangeValid(apcRoutine, 1)) { auto& thread = m_threads[m_currentThreadIndex]; thread.apcs.push_back({ 0, 0, 0, apcRoutine, apcContext, iosb, 0, true }); Write(thread.guestThread + 0x4A, static_cast<std::uint8_t>(1)); }
		WakeThreads(); SyncReadyList();
		m_regs->eax = status; FinishStdcall(8); break;
	}
	case 220: case 237: { // NtReadFileScatter / NtWriteFileGather
		std::uint32_t eventHandle = 0, apcRoutine = 0, apcContext = 0, iosb = 0;
		std::uint32_t segments = 0, length = 0, offsetAddress = 0;
		if (!ReadStack(0, a) || !ReadStack(1, eventHandle) || !ReadStack(2, apcRoutine) ||
			!ReadStack(3, apcContext) || !ReadStack(4, iosb) || !ReadStack(5, segments) ||
			!ReadStack(6, length) || !ReadStack(7, offsetAddress)) return Unsupported(ordinal);
		ObjectPtr completionEvent;
		if (eventHandle) completionEvent = GetHandle(eventHandle);
		if ((eventHandle && (!completionEvent || completionEvent->kind != ObjectKind::Event)) ||
			(apcRoutine && !IsRangeValid(apcRoutine, 1))) {
			const std::uint32_t failure = eventHandle && (!completionEvent || completionEvent->kind != ObjectKind::Event) ?
				StatusInvalidHandle : StatusInvalidParameter;
			if (IsRangeValid(iosb, 8)) WriteIoStatus(iosb, failure, 0);
			m_regs->eax = failure; FinishStdcall(8); break;
		}
		auto object = GetHandle(a); std::uint32_t status = StatusInvalidHandle, total = 0;
		const std::uint32_t segmentCount = static_cast<std::uint32_t>((static_cast<std::uint64_t>(length) + 4095u) >> 12);
		if (!iosb || !IsRangeValid(iosb, 8) || (segmentCount && !IsRangeValid(segments, segmentCount * 4u))) status = StatusInvalidParameter;
		else if (object && object->kind == ObjectKind::File) {
			if (object->guestAddress) { object->signaled = false; SyncDispatcherSignal(object); }
			std::uint64_t offset = object->xisoPosition;
			status = StatusSuccess;
			if (offsetAddress) {
				std::int64_t requested = 0;
				if (!Read(offsetAddress, requested) || requested < 0) status = StatusInvalidParameter;
				else offset = static_cast<std::uint64_t>(requested);
			}
			if (object->xiso && ordinal == 237) status = StatusAccessDenied;
			if (!object->xiso && object->nativeHandle == INVALID_HANDLE_VALUE) status = StatusInvalidHandle;
			if (status == StatusSuccess && !object->xiso) {
				LARGE_INTEGER move = {}; move.QuadPart = static_cast<LONGLONG>(offset);
				if (!SetFilePointerEx(object->nativeHandle, move, nullptr, FILE_BEGIN)) status = StatusFromWin32(GetLastError());
			}
			for (std::uint32_t index = 0; status == StatusSuccess && total < length; ++index) {
				std::uint32_t page = 0; Read(segments + index * 4u, page);
				const std::uint32_t chunk = (std::min)(4096u, length - total);
				if (!page || (page & 0xFFFu) || !IsRangeValid(page, chunk)) { status = StatusInvalidParameter; break; }
				std::uint32_t done = 0;
				if (object->xiso) {
					const HRESULT result = object->xisoVolume ? m_xiso->ReadImage(offset + total, GuestPointer(page, chunk), chunk, done) :
						m_xiso->Read(object->xisoEntry, offset + total, GuestPointer(page, chunk), chunk, done);
					if (FAILED(result)) status = StatusFromWin32(HRESULT_CODE(result));
				} else {
					DWORD transferred = 0;
					const BOOL ok = ordinal == 220 ? ReadFile(object->nativeHandle, GuestPointer(page, chunk), chunk, &transferred, nullptr) :
						WriteFile(object->nativeHandle, GuestPointer(page, chunk), chunk, &transferred, nullptr);
					done = transferred; if (!ok) status = StatusFromWin32(GetLastError());
				}
				total += done; if (done < chunk) break;
			}
			object->xisoPosition = offset + total;
			if (object->guestAddress) Write(object->guestAddress + 0x14, offset + total);
		}
		WriteIoStatus(iosb, status, total);
		SignalFileCompletion(object, status);
		if (completionEvent) { completionEvent->signaled = true; SyncDispatcherSignal(completionEvent); m_objectChanged.notify_all(); }
		if (apcRoutine && IsRangeValid(apcRoutine, 1)) { auto& thread = m_threads[m_currentThreadIndex]; thread.apcs.push_back({ 0, 0, 0, apcRoutine, apcContext, iosb, 0, true }); Write(thread.guestThread + 0x4A, static_cast<std::uint8_t>(1)); }
		WakeThreads(); SyncReadyList(); m_regs->eax = status; FinishStdcall(8); break;
	}
	case 221: { // NtReleaseMutant
		if (!ReadStack(0, a) || !ReadStack(1, b) || (b && !IsRangeValid(b, 4))) return Unsupported(ordinal); auto object = GetHandle(a);
		if (!object) m_regs->eax = StatusInvalidHandle;
		else if (object->kind != ObjectKind::Mutant) m_regs->eax = 0xC0000024u;
		else if (object->ownerThreadId != m_threads[m_currentThreadIndex].id) m_regs->eax = 0xC0000046u;
		else {
			c = object->recursionCount > 0 ? 1u - object->recursionCount : 1u;
			if (object->recursionCount > 1) {
				--object->recursionCount;
				if (object->guestAddress) Write(object->guestAddress + 4, static_cast<std::int32_t>(1 - object->recursionCount));
			} else {
				object->recursionCount = 0; object->ownerThreadId = 0; object->signaled = true;
				if (object->guestAddress) {
					UnlinkMutant(object);
					Write(object->guestAddress + 4, 1u); Write(object->guestAddress + 0x18, 0u);
					Write(object->guestAddress + 0x1C, static_cast<std::uint8_t>(0));
				}
			}
			if (b) Write(b, c);
			SyncDispatcherSignal(object); m_objectChanged.notify_all(); WakeThreads(); SyncReadyList();
			m_regs->eax = StatusSuccess;
		}
		FinishStdcall(2); break;
	}
	case 222: { // NtReleaseSemaphore
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || (c && !IsRangeValid(c, 4))) return Unsupported(ordinal); auto object = GetHandle(a);
		if (!object) m_regs->eax = StatusInvalidHandle;
		else if (object->kind != ObjectKind::Semaphore) m_regs->eax = 0xC0000024u;
		else if (!b || b > static_cast<std::uint32_t>(object->limit - object->count)) m_regs->eax = 0xC0000047u;
		else { d = object->count; object->count += b; SyncDispatcherSignal(object); if (c) Write(c, d); m_objectChanged.notify_all(); WakeThreads(); SyncReadyList(); m_regs->eax = StatusSuccess; } FinishStdcall(3); break;
	}
	case 223: { // NtRemoveIoCompletion
		std::uint32_t keyOut = 0, apcOut = 0, iosbOut = 0, timeout = 0;
		if (!ReadStack(0, a) || !ReadStack(1, keyOut) || !ReadStack(2, apcOut) ||
			!ReadStack(3, iosbOut) || !ReadStack(4, timeout)) return Unsupported(ordinal);
		if (!keyOut || !apcOut || !iosbOut || !IsRangeValid(keyOut, 4) ||
			!IsRangeValid(apcOut, 4) || !IsRangeValid(iosbOut, 8) ||
			(timeout && !IsRangeValid(timeout, 8))) {
			m_regs->eax = StatusInvalidParameter; FinishStdcall(5); break;
		}
		auto object = GetHandle(a);
		if (!object || object->kind != ObjectKind::IoCompletion) {
			m_regs->eax = StatusInvalidHandle; FinishStdcall(5);
		} else if (!object->completions.empty()) {
			const auto packet = object->completions.front(); object->completions.pop_front();
			Write(keyOut, packet[0]); Write(apcOut, packet[1]); WriteIoStatus(iosbOut, packet[2], packet[3]);
			object->signaled = !object->completions.empty(); SyncDispatcherSignal(object);
			m_regs->eax = StatusSuccess; FinishStdcall(5);
		} else {
			FinishStdcall(5); auto& thread = m_threads[m_currentThreadIndex];
			thread.completionKeyOut = keyOut; thread.completionApcOut = apcOut; thread.completionIosbOut = iosbOut;
			ScheduleWait({ object }, false, false, timeout);
		}
		break;
	}
	case 225: { // NtSetEvent
		if (!ReadStack(0, a) || !ReadStack(1, b) || (b && !IsRangeValid(b, 4))) return Unsupported(ordinal); auto object = GetHandle(a);
		if (!object) m_regs->eax = StatusInvalidHandle;
		else if (object->kind != ObjectKind::Event) m_regs->eax = 0xC0000024u;
		else { c = object->signaled ? 1 : 0; object->signaled = true; SyncDispatcherSignal(object); if (b) Write(b, c); m_objectChanged.notify_all(); WakeThreads(); SyncReadyList(); m_regs->eax = StatusSuccess; } FinishStdcall(2); break;
	}
	case 226: { // NtSetInformationFile
		std::uint32_t iosb = 0, buffer = 0, length = 0, infoClass = 0;
		if (!ReadStack(0, a) || !ReadStack(1, iosb) || !ReadStack(2, buffer) || !ReadStack(3, length) ||
			!ReadStack(4, infoClass) || !IsRangeValid(iosb, 8)) return Unsupported(ordinal);
		auto object = GetHandle(a); std::uint32_t status = StatusInvalidHandle;
		if (object && object->xiso) {
			if (infoClass == 14 && length >= 8) { // FilePositionInformation
				std::int64_t value = 0;
				if (Read(buffer, value) && value >= 0) { object->xisoPosition = value; if (object->guestAddress) Write(object->guestAddress + 0x14, static_cast<std::uint64_t>(value)); status = StatusSuccess; }
				else status = StatusInvalidParameter;
			} else {
				// XISO contents are deliberately mounted in place and read-only.
				status = StatusAccessDenied;
			}
		}
		else if (object && object->brokeredOptical && object->nativeHandle == INVALID_HANDLE_VALUE) {
			status = StatusAccessDenied;
		}
		else if (object && object->nativeHandle != INVALID_HANDLE_VALUE) {
			if (infoClass == 4 && length >= 40 && IsRangeValid(buffer, 40)) { // FileBasicInformation
				FILE_BASIC_INFO info = {}; std::uint64_t value = 0;
				Read(buffer, value); info.CreationTime.QuadPart = value; Read(buffer + 8, value); info.LastAccessTime.QuadPart = value;
				Read(buffer + 16, value); info.LastWriteTime.QuadPart = value; Read(buffer + 24, value); info.ChangeTime.QuadPart = value;
				Read(buffer + 32, info.FileAttributes);
				status = SetFileInformationByHandle(object->nativeHandle, FileBasicInfo, &info, sizeof(info)) ? StatusSuccess : StatusFromWin32(GetLastError());
			}
			else if ((infoClass == 10 || infoClass == 11) && length >= 16 && IsRangeValid(buffer, 16)) { // Rename / Link
				std::uint32_t rootHandle = 0, nameBuffer = 0; std::uint16_t nameLength = 0;
				Read(buffer + 4, rootHandle); Read(buffer + 8, nameLength); Read(buffer + 12, nameBuffer);
				if (!IsRangeValid(nameBuffer, nameLength)) status = StatusInvalidParameter;
				else {
					std::wstring relative; for (std::uint32_t i = 0; i < nameLength; ++i) { std::uint8_t character = 0; Read(nameBuffer + i, character); relative.push_back(static_cast<wchar_t>(character)); }
					std::replace(relative.begin(), relative.end(), L'/', L'\\');
					std::wstring base; if (rootHandle) { auto root = GetHandle(rootHandle); if (root && root->kind == ObjectKind::Directory) base = root->path; }
					else { base = object->path; const auto slash = base.find_last_of(L"\\/"); base = slash == std::wstring::npos ? L"" : base.substr(0, slash); }
					if (base.empty() || relative.empty() || relative.find(L"..") != std::wstring::npos || relative.find_first_of(L"<>|\"?*") != std::wstring::npos) status = StatusInvalidParameter;
					else {
						while (!relative.empty() && relative.front() == L'\\') relative.erase(relative.begin());
					std::uint8_t replaceByte = 0; Read(buffer, replaceByte); const std::wstring target = base + L"\\" + relative; const bool replace = replaceByte != 0;
						if (infoClass == 10) {
							if (replace) { DeleteFileFromAppW(target.c_str()); RemoveDirectoryFromAppW(target.c_str()); }
							status = MoveFileFromAppW(object->path.c_str(), target.c_str()) ? StatusSuccess : StatusFromWin32(GetLastError());
							if (status == StatusSuccess) object->path = target;
						} else status = StatusInvalidDeviceRequest; // UWP exposes no broker-safe hard-link primitive.
					}
				}
			}
			else if (infoClass == 13 && length >= 1 && IsRangeValid(buffer, 1)) { // FileDispositionInformation
				std::uint8_t deleteByte = 0; Read(buffer, deleteByte); object->deleteOnClose = deleteByte != 0;
				status = StatusSuccess;
			}
			else if (infoClass == 14 && length >= 8) { // FilePositionInformation
				std::int64_t value = 0;
				if (!Read(buffer, value) || value < 0) status = StatusInvalidParameter;
				else { LARGE_INTEGER move = {}; move.QuadPart = value; status = SetFilePointerEx(object->nativeHandle, move, nullptr, FILE_BEGIN) ? StatusSuccess : StatusFromWin32(GetLastError()); if (status == StatusSuccess && object->guestAddress) Write(object->guestAddress + 0x14, static_cast<std::uint64_t>(value)); }
			}
			else if (infoClass == 16 && length >= 4 && IsRangeValid(buffer, 4)) { // FileModeInformation
				Read(buffer, object->openOptions);
				if (object->guestAddress) {
					std::uint8_t flags = 0x20;
					if (object->openOptions & (0x10u | 0x20u)) flags |= 0x01;
					if (object->openOptions & 0x10u) flags |= 0x02;
					if (object->openOptions & 0x08u) flags |= 0x04;
					if (object->openOptions & 0x04u) flags |= 0x08;
					if (object->openOptions & 0x800u) flags |= 0x40;
					Write(object->guestAddress + 3, flags);
				}
				status = StatusSuccess;
			}
			else if ((infoClass == 19 || infoClass == 20) && length >= 8) { // Allocation / EOF
				std::int64_t value = 0;
				if (!Read(buffer, value) || value < 0) status = StatusInvalidParameter;
				else if (infoClass == 19) {
					FILE_ALLOCATION_INFO allocation = {}; allocation.AllocationSize.QuadPart = value;
					status = SetFileInformationByHandle(object->nativeHandle, FileAllocationInfo, &allocation, sizeof(allocation)) ? StatusSuccess : StatusFromWin32(GetLastError());
				} else {
					FILE_END_OF_FILE_INFO eof = {}; eof.EndOfFile.QuadPart = value;
					status = SetFileInformationByHandle(object->nativeHandle, FileEndOfFileInfo, &eof, sizeof(eof)) ? StatusSuccess : StatusFromWin32(GetLastError());
				}
			}
			else status = StatusInvalidParameter;
		}
		WriteIoStatus(iosb, status, 0);
		SignalFileCompletion(object, status); WakeThreads(); SyncReadyList();
		m_regs->eax = status; FinishStdcall(5); break;
	}
	case 227: { // NtSetIoCompletion
		std::uint32_t key = 0, apc = 0, status = 0, information = 0; if (!ReadStack(0, a) || !ReadStack(1, key) || !ReadStack(2, apc) || !ReadStack(3, status) || !ReadStack(4, information)) return Unsupported(ordinal); auto object = GetHandle(a); if (!object || object->kind != ObjectKind::IoCompletion) m_regs->eax = StatusInvalidHandle; else { object->completions.push_back({ key, apc, status, information }); object->signaled = true; SyncDispatcherSignal(object); m_objectChanged.notify_all(); WakeThreads(); SyncReadyList(); m_regs->eax = StatusSuccess; } FinishStdcall(5); break;
	}
	case 228: { // NtSetSystemTime (virtualized per emulation session)
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 8)) return Unsupported(ordinal); FILETIME now = {}; GetSystemTimeAsFileTime(&now); const std::uint64_t current = (static_cast<std::uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime; if (b) Write(b, current + m_systemTimeOffset); std::uint64_t requested = 0; Read(a, requested); m_systemTimeOffset = static_cast<std::int64_t>(requested - current); m_regs->eax = StatusSuccess; FinishStdcall(2); break;
	}
	case 229: { // NtSetTimerEx
		std::uint32_t apcRoutine = 0, apcMode = 0, apcContext = 0, wakeTimer = 0;
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, apcRoutine) ||
			!ReadStack(3, apcMode) || !ReadStack(4, apcContext) || !ReadStack(5, wakeTimer) ||
			!ReadStack(6, c) || !ReadStack(7, d)) return Unsupported(ordinal); auto object = GetHandle(a);
		if (!object) m_regs->eax = StatusInvalidHandle;
		else if (object->kind != ObjectKind::Timer) m_regs->eax = 0xC0000024u;
		else if (!b || !IsRangeValid(b, 8) || static_cast<std::int32_t>(c) < 0 || apcMode > 1 ||
			(apcRoutine && !IsRangeValid(apcRoutine, 1))) m_regs->eax = StatusInvalidParameter;
		else {
			bool infinite = false; auto due = DecodeDeadline(b, infinite); const bool previous = object->timerActive;
			object->timerActive = true; object->signaled = false; object->due = due;
			if (object->guestAddress) Write(object->guestAddress + 3, static_cast<std::uint8_t>(1));
			SyncDispatcherSignal(object);
			object->period = std::chrono::milliseconds(c); object->timerDpc = 0;
			object->timerApcRoutine = apcRoutine; object->timerApcContext = apcContext;
			object->timerThreadId = m_threads.empty() ? 0 : m_threads[m_currentThreadIndex].id;
			object->timerApcUserMode = apcMode != 0;
			(void)wakeTimer; // No suspend/resume power state exists inside the UWP guest VM.
			if (d) Write(d, previous ? std::uint8_t(1) : std::uint8_t(0));
			m_objectChanged.notify_all(); m_regs->eax = StatusSuccess;
		} FinishStdcall(8); break;
	}
	case 230: { // NtSignalAndWaitForSingleObjectEx
		std::uint32_t waitMode = 0, alertable = 0, timeout = 0; if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, waitMode) || !ReadStack(3, alertable) || !ReadStack(4, timeout)) return Unsupported(ordinal);
		if (waitMode > 1) { m_regs->eax = StatusInvalidParameter; FinishStdcall(5); break; }
		auto signal = GetHandle(a); auto wait = GetHandle(b);
		if (!signal || !wait) m_regs->eax = StatusInvalidHandle;
		else {
			std::uint32_t signalStatus = StatusSuccess;
			switch (signal->kind) {
			case ObjectKind::Event:
				signal->signaled = true;
				break;
			case ObjectKind::Semaphore:
				if (signal->count >= signal->limit) signalStatus = 0xC0000047u;
				else ++signal->count;
				break;
			case ObjectKind::Mutant:
				if (signal->ownerThreadId != m_threads[m_currentThreadIndex].id) signalStatus = 0xC0000046u;
				else if (signal->recursionCount > 1) --signal->recursionCount;
				else {
					signal->recursionCount = 0; signal->ownerThreadId = 0; signal->signaled = true;
					if (signal->guestAddress) {
						UnlinkMutant(signal);
						Write(signal->guestAddress + 0x18, 0u);
						Write(signal->guestAddress + 0x1C, static_cast<std::uint8_t>(0));
					}
				}
				break;
			default:
				signalStatus = StatusInvalidParameter;
				break;
			}
			if (signalStatus != StatusSuccess) { m_regs->eax = signalStatus; FinishStdcall(5); break; }
			SyncDispatcherSignal(signal); m_objectChanged.notify_all();
			if (m_currentThreadIndex < m_threads.size()) {
				Write(m_threads[m_currentThreadIndex].guestThread + 0x56, static_cast<std::uint8_t>(1));
				Write(m_threads[m_currentThreadIndex].guestThread + 0x54, m_currentIrql);
			}
			FinishStdcall(5); ScheduleWait({ wait }, false, alertable != 0, timeout, static_cast<std::uint8_t>(waitMode), 0); break;
		}
		FinishStdcall(5); break;
	}
	case 224: { // NtResumeThread
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal); auto* thread = FindThreadByHandle(a);
		if (!thread) m_regs->eax = StatusInvalidHandle; else { const std::uint32_t previous = thread->suspendCount; if (b) Write(b, previous); if (thread->suspendCount) --thread->suspendCount; Write(thread->guestThread + 0x75, static_cast<std::uint8_t>(thread->suspendCount)); if (!thread->suspendCount) { Write(thread->guestThread + 0xF4, 1u); Write(thread->guestThread + 0xCB, static_cast<std::uint8_t>(0)); if (thread->state == ThreadState::Suspended) { thread->state = ThreadState::Runnable; Write(thread->guestThread + 0x2C, static_cast<std::uint8_t>(1)); } } m_regs->eax = StatusSuccess; } WakeThreads(); SyncReadyList(); FinishStdcall(2); break;
	}
	case 231: { // NtSuspendThread
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal); auto* thread = FindThreadByHandle(a);
		if (!thread) m_regs->eax = StatusInvalidHandle; else if (thread->suspendCount >= 0x7F) m_regs->eax = 0xC000004Au; else { std::uint8_t apcQueueable = 0; Read(thread->guestThread + 0x4B, apcQueueable); const std::uint32_t previous = thread->suspendCount; if (b) Write(b, previous); if (apcQueueable) { ++thread->suspendCount; Write(thread->guestThread + 0x75, static_cast<std::uint8_t>(thread->suspendCount)); if (previous == 0) { Write(thread->guestThread + 0xF4, 0u); Write(thread->guestThread + 0xCB, static_cast<std::uint8_t>(1)); } Write(thread->guestThread + 0x2C, static_cast<std::uint8_t>(5)); } m_regs->eax = StatusSuccess; FinishStdcall(2); if (apcQueueable) { if (thread == &m_threads[m_currentThreadIndex]) { thread->regs = *m_regs; thread->state = ThreadState::Suspended; SwitchThread(false); } else if (thread->state == ThreadState::Runnable || thread->state == ThreadState::Running) thread->state = ThreadState::Suspended; } break; } FinishStdcall(2); break;
	}
	case 232: // NtUserIoApcDispatcher (APC already injected by scheduler)
		FinishStdcall(3); break;
	case 233: case 234: { // NtWaitForSingleObject[Ex]
		if (!ReadStack(0, a)) return Unsupported(ordinal); auto object = GetHandle(a); std::uint32_t waitMode = 0, alertable = 0, timeout = 0;
		if (ordinal == 234 && !ReadStack(1, waitMode)) return Unsupported(ordinal);
		if (ordinal == 234 && waitMode > 1) { m_regs->eax = StatusInvalidParameter; FinishStdcall(4); break; }
		if (!ReadStack(ordinal == 233 ? 1 : 2, alertable) || !ReadStack(ordinal == 233 ? 2 : 3, timeout)) return Unsupported(ordinal);
		if (!object) { m_regs->eax = StatusInvalidHandle; FinishStdcall(ordinal == 233 ? 3 : 4); break; }
		FinishStdcall(ordinal == 233 ? 3 : 4); ScheduleWait({ object }, false, alertable != 0, timeout, static_cast<std::uint8_t>(waitMode), 0); break;
	}
	case 235: { // NtWaitForMultipleObjectsEx
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c)) return Unsupported(ordinal);
		if (a == 0 || a > 64 || !IsRangeValid(b, a * 4)) { m_regs->eax = StatusInvalidParameter; FinishStdcall(6); break; }
		std::vector<ObjectPtr> objects;
		for (std::uint32_t i = 0; i < a; ++i) { std::uint32_t handle = 0; Read(b + i * 4, handle); auto object = GetHandle(handle); if (!object) { m_regs->eax = StatusInvalidHandle; FinishStdcall(6); return; } if (std::any_of(objects.begin(), objects.end(), [&object](const ObjectPtr& existing) { return existing.get() == object.get(); })) { m_regs->eax = StatusInvalidParameter; FinishStdcall(6); return; } objects.push_back(object); }
		std::uint32_t waitMode = 0, alertable = 0, timeout = 0; if (!ReadStack(3, waitMode) || !ReadStack(4, alertable) || !ReadStack(5, timeout)) return Unsupported(ordinal);
		if (waitMode > 1) { m_regs->eax = StatusInvalidParameter; FinishStdcall(6); break; }
		FinishStdcall(6); ScheduleWait(std::move(objects), c == 0, alertable != 0, timeout, static_cast<std::uint8_t>(waitMode), 0); break;
	}
	case 238: // NtYieldExecution
		m_regs->eax = StatusSuccess; FinishStdcall(0); SwitchThread(true); break;
	case 239: { // ObCreateObject
		std::uint32_t type = 0, attributes = 0, bodySize = 0, objectOut = 0;
		if (!ReadStack(0, type) || !ReadStack(1, attributes) || !ReadStack(2, bodySize) || !ReadStack(3, objectOut) ||
			!IsRangeValid(type, 28) || !IsRangeValid(objectOut, 4) || (attributes && !IsRangeValid(attributes, 12))) return Unsupported(ordinal);
		Write(objectOut, 0u);
		auto object = std::make_shared<KernelObject>(); object->objectType = type;
		object->references = 1; object->guestBodySize = bodySize;
		if (type == DataAddress(16)) object->kind = ObjectKind::Event;
		else if (type == DataAddress(22)) object->kind = ObjectKind::Mutant;
		else if (type == DataAddress(30)) object->kind = ObjectKind::Semaphore;
		else if (type == DataAddress(31)) object->kind = ObjectKind::Timer;
		else if (type == DataAddress(64)) object->kind = ObjectKind::IoCompletion;
		else if (type == DataAddress(71)) object->kind = ObjectKind::File;
		else if (type == DataAddress(249)) object->kind = ObjectKind::SymbolicLink;
		else if (type == DataAddress(259)) object->kind = ObjectKind::Thread;
		else object->kind = ObjectKind::Directory;
		if (attributes) {
			std::uint32_t nameDescriptor = 0; Read(attributes + 4, nameDescriptor);
			if (nameDescriptor) {
				std::wstring name; std::uint32_t root = 0;
				if (!ReadObjectName(attributes, name, root) || name.empty() || name.back() == L'\\' ||
					name.find(L"\\\\") != std::wstring::npos) {
					m_regs->eax = 0xC0000033u; FinishStdcall(4); break;
				}
				const std::size_t separator = name.find_last_of(L'\\');
				const std::wstring leaf = separator == std::wstring::npos ? name : name.substr(separator + 1);
				if (leaf.empty() || leaf.find(L'\\') != std::wstring::npos) {
					m_regs->eax = 0xC0000033u; FinishStdcall(4); break;
				}
				object->path = leaf;
			}
		}
		if (!EnsureGuestObjectBody(object)) { m_regs->eax = StatusNoMemory; FinishStdcall(4); break; }
		Write(objectOut, object->guestAddress); m_regs->eax = StatusSuccess; FinishStdcall(4); break;
	}
	case 241: { // ObInsertObject
		std::uint32_t attributes = 0, bias = 0;
		if (!ReadStack(0, a) || !ReadStack(1, attributes) || !ReadStack(2, bias) || !ReadStack(3, b) ||
			!IsRangeValid(b, 4) || (attributes && !IsRangeValid(attributes, 12))) return Unsupported(ordinal); ObjectPtr object;
		Write(b, 0u);
		{ std::lock_guard<std::mutex> lock(m_objectMutex); auto found = m_guestObjects.find(a); if (found != m_guestObjects.end()) object = found->second; }
		if (!object) m_regs->eax = StatusInvalidParameter; else {
			ObjectPtr insertObject = object;
			std::uint32_t resultStatus = StatusSuccess;
			std::uint32_t attributeFlags = 0;
			if (attributes) Read(attributes + 8, attributeFlags);
			if (attributes) {
				std::uint32_t nameDescriptor = 0; Read(attributes + 4, nameDescriptor);
				if (nameDescriptor) {
					std::wstring name;
					const std::uint32_t resolveStatus = ResolveObjectName(attributes, name);
					if (resolveStatus != StatusSuccess) { m_regs->eax = resolveStatus; DereferenceObject(object, true); FinishStdcall(4); break; }
					const std::wstring key = NormalizeObjectName(name);
					auto existing = m_namedObjects.find(key);
					if (existing != m_namedObjects.end()) {
						if ((attributeFlags & 0x80u) == 0) { m_regs->eax = StatusObjectNameCollision; DereferenceObject(object, true); FinishStdcall(4); break; }
						if (existing->second->objectType && object->objectType && existing->second->objectType != object->objectType) { m_regs->eax = 0xC0000024u; DereferenceObject(object, true); FinishStdcall(4); break; }
						insertObject = existing->second; resultStatus = 0x40000000u;
					} else {
						const std::size_t separator = name.find_last_of(L'\\');
						const std::wstring parentName = separator == 0 ? L"\\" : name.substr(0, separator);
						auto parent = m_namedObjects.find(NormalizeObjectName(parentName));
						if (parent == m_namedObjects.end() || parent->second->kind != ObjectKind::Directory ||
							parent->second->objectType != DataAddress(240)) {
							m_regs->eax = 0xC000003Au; DereferenceObject(object, true); FinishStdcall(4); break;
						}
						object->path = name; object->attached = true; m_namedObjects[key] = object;
						++object->references;
						if (object->allocationBase) { std::uint32_t flags = 0; Read(object->allocationBase + 12, flags); Write(object->allocationBase, object->references); Write(object->allocationBase + 12, flags | 4u); }
					}
				}
			}
			if (attributeFlags & 0x10u) { insertObject->permanent = true; if (insertObject->allocationBase) { std::uint32_t flags = 0; Read(insertObject->allocationBase + 12, flags); Write(insertObject->allocationBase + 12, flags | 2u); } }
			insertObject->references += bias; if (insertObject->allocationBase) Write(insertObject->allocationBase, insertObject->references);
			const std::uint32_t handleStatus = CreateOutputHandle(insertObject, b);
			if (handleStatus != StatusSuccess) {
				insertObject->references -= bias; if (insertObject->allocationBase) Write(insertObject->allocationBase, insertObject->references);
				if (insertObject.get() == object.get() && object->attached) {
					if (!object->path.empty()) m_namedObjects.erase(NormalizeObjectName(object->path));
					object->attached = false;
					if (object->references) --object->references;
					if (object->allocationBase) { std::uint32_t flags = 0; Read(object->allocationBase + 12, flags); Write(object->allocationBase, object->references); Write(object->allocationBase + 12, flags & ~4u); }
				}
				m_regs->eax = handleStatus;
			} else m_regs->eax = resultStatus;
			// Transfer the reference returned by ObCreateObject. On success the new
			// handle (plus ObjectPointerBias) owns the remaining references.
			DereferenceObject(object, true);
		} FinishStdcall(4); break;
	}
	case 242: { // ObMakeTemporaryObject
		if (!ReadStack(0, a)) return Unsupported(ordinal); ObjectPtr object;
		{ std::lock_guard<std::mutex> lock(m_objectMutex); auto found = m_guestObjects.find(a); if (found != m_guestObjects.end()) object = found->second; }
		if (object) { object->permanent = false; if (object->allocationBase) { std::uint32_t flags = 0; Read(object->allocationBase + 12, flags); Write(object->allocationBase + 12, flags & ~2u); } }
		if (object && object->attached && object->allocationBase) {
			std::uint32_t handles = 0; Read(object->allocationBase + 4, handles);
			if (!handles) {
				if (!object->path.empty()) m_namedObjects.erase(NormalizeObjectName(object->path));
				object->attached = false;
				std::uint32_t flags = 0; Read(object->allocationBase + 12, flags); Write(object->allocationBase + 12, flags & ~4u);
				DereferenceObject(object, true);
			}
		}
		if (object) DereferenceObject(object, false);
		FinishStdcall(1); break;
	}
	case 243: { // ObOpenObjectByName
		std::uint32_t type = 0, handleOut = 0; if (!ReadStack(0, a) || !ReadStack(1, type) || !ReadStack(3, handleOut) || !IsRangeValid(handleOut, 4)) return Unsupported(ordinal); Write(handleOut, 0u); std::wstring name; const std::uint32_t resolveStatus = ResolveObjectName(a, name); if (resolveStatus != StatusSuccess) m_regs->eax = resolveStatus; else { auto found = m_namedObjects.find(NormalizeObjectName(name)); if (found == m_namedObjects.end()) m_regs->eax = StatusObjectNameNotFound; else if (type && found->second->objectType && type != found->second->objectType) m_regs->eax = 0xC0000024u; else m_regs->eax = CreateOutputHandle(found->second, handleOut); } FinishStdcall(4); break;
	}
	case 244: { // ObOpenObjectByPointer
		std::uint32_t type = 0;
		if (!ReadStack(0, a) || !ReadStack(1, type) || !ReadStack(2, b) || !IsRangeValid(b, 4)) return Unsupported(ordinal); Write(b, 0u); ObjectPtr object;
		{ std::lock_guard<std::mutex> lock(m_objectMutex); auto found = m_guestObjects.find(a); if (found != m_guestObjects.end()) object = found->second; }
		if (!object) m_regs->eax = StatusInvalidParameter;
		else if (type && object->objectType && type != object->objectType) m_regs->eax = 0xC0000024u;
		else m_regs->eax = CreateOutputHandle(object, b); FinishStdcall(3); break;
	}
	case 246: { // ObReferenceObjectByHandle
		std::uint32_t type = 0; if (!ReadStack(0, a) || !ReadStack(1, type) || !ReadStack(2, b) || !IsRangeValid(b, 4)) return Unsupported(ordinal); auto object = GetHandle(a);
		if (!object) m_regs->eax = StatusInvalidHandle; else if (type && object->objectType && type != object->objectType) m_regs->eax = 0xC0000024u; else { ++object->references; if (object->allocationBase) Write(object->allocationBase, object->references); Write(b, object->guestAddress); m_regs->eax = StatusSuccess; } FinishStdcall(3); break;
	}
	case 247: { // ObReferenceObjectByName
		std::uint32_t type = 0, objectOut = 0; if (!ReadStack(0, a) || !ReadStack(2, type) || !ReadStack(4, objectOut) || !IsRangeValid(a, 8) || !IsRangeValid(objectOut, 4)) return Unsupported(ordinal); Write(objectOut, 0u); std::uint16_t length = 0, maximum = 0; std::uint32_t buffer = 0; Read(a, length); Read(a + 2, maximum); Read(a + 4, buffer); if (length > maximum || (length && !IsRangeValid(buffer, length))) return Unsupported(ordinal); std::wstring name; for (std::uint32_t i = 0; i < length; ++i) { std::uint8_t character = 0; Read(buffer + i, character); name.push_back(static_cast<wchar_t>(character)); } auto found = m_namedObjects.find(NormalizeObjectName(name)); if (found == m_namedObjects.end()) m_regs->eax = StatusObjectNameNotFound; else if (type && found->second->objectType && type != found->second->objectType) m_regs->eax = 0xC0000024u; else { ++found->second->references; if (found->second->allocationBase) Write(found->second->allocationBase, found->second->references); Write(objectOut, found->second->guestAddress); m_regs->eax = StatusSuccess; } FinishStdcall(5); break;
	}
	case 248: { // ObReferenceObjectByPointer
		std::uint32_t type = 0; if (!ReadStack(0, a) || !ReadStack(1, type)) return Unsupported(ordinal); ObjectPtr object;
		{ std::lock_guard<std::mutex> lock(m_objectMutex); auto found = m_guestObjects.find(a); if (found != m_guestObjects.end()) object = found->second; }
		if (object && type == object->objectType) { ++object->references; if (object->allocationBase) Write(object->allocationBase, object->references); m_regs->eax = StatusSuccess; } else m_regs->eax = object ? 0xC0000024u : StatusInvalidParameter; FinishStdcall(2); break;
	}
	case 250: case 251: { // ObfDereferenceObject / ObfReferenceObject, fastcall
		a = m_regs->ecx; ObjectPtr object; { std::lock_guard<std::mutex> lock(m_objectMutex); auto found = m_guestObjects.find(a); if (found != m_guestObjects.end()) object = found->second; }
		if (object) { if (ordinal == 251) { ++object->references; if (object->allocationBase) Write(object->allocationBase, object->references); } else DereferenceObject(object, true); }
		FinishFastcall(); break;
	}
	case 252: // PhyGetLinkState
		if (!ReadStack(0, a)) return Unsupported(ordinal); m_regs->eax = 0x0Bu; FinishStdcall(1); break;
	case 253: // PhyInitialize
		m_regs->eax = StatusSuccess; FinishStdcall(2); break;
	case 254: { // PsCreateSystemThread
		std::uint32_t idOut = 0, start = 0, context = 0, debuggerThread = 0;
		if (!ReadStack(0, a) || !ReadStack(1, idOut) || !ReadStack(2, start) || !ReadStack(3, context) || !ReadStack(4, debuggerThread)) return Unsupported(ordinal);
		(void)debuggerThread; // UWP has one guest RAM pool; debug stacks use the same allocator.
		m_regs->eax = CreateGuestThread(start, context, 0, 64u * 1024u, false, a, idOut); FinishStdcall(5); DeliverThreadNotification(); break;
	}
	case 255: { // PsCreateSystemThreadEx
		std::uint32_t extensionSize = 0, stackSize = 0, tlsDataSize = 0;
		std::uint32_t idOut = 0, start = 0, context = 0, suspended = 0, debuggerThread = 0, system = 0;
		if (!ReadStack(0, a) || !ReadStack(1, extensionSize) || !ReadStack(2, stackSize) ||
			!ReadStack(3, tlsDataSize) || !ReadStack(4, idOut) || !ReadStack(5, start) ||
			!ReadStack(6, context) || !ReadStack(7, suspended) || !ReadStack(8, debuggerThread) || !ReadStack(9, system)) return Unsupported(ordinal);
		(void)debuggerThread;
		m_regs->eax = CreateGuestThread(start, context, system, stackSize,
			suspended != 0, a, idOut, extensionSize, tlsDataSize);
		FinishStdcall(10);
		DeliverThreadNotification();
		break;
	}
	case 256: { // PsQueryStatistics
		if (!ReadStack(0, a) || !IsRangeValid(a, 12)) return Unsupported(ordinal); std::uint32_t length = 0; Read(a, length);
		if (length < 12) m_regs->eax = StatusInvalidParameter; else { std::uint32_t count = 0; for (const auto& thread : m_threads) if (thread.state != ThreadState::Terminated) ++count; Write(a + 4, count); Write(a + 8, static_cast<std::uint32_t>(m_handles.size())); m_regs->eax = StatusSuccess; }
		FinishStdcall(1); break;
	}
	case 257: { // PsSetCreateThreadNotifyRoutine
		if (!ReadStack(0, a) || !a || !IsRangeValid(a, 1)) return Unsupported(ordinal);
		if (std::find(m_threadNotifyRoutines.begin(), m_threadNotifyRoutines.end(), a) != m_threadNotifyRoutines.end()) m_regs->eax = StatusObjectNameCollision;
		else if (m_threadNotifyRoutines.size() >= 8) m_regs->eax = 0xC000009Au;
		else { m_threadNotifyRoutines.push_back(a); m_regs->eax = StatusSuccess; }
		FinishStdcall(1); break;
	}
	case 258: // PsTerminateSystemThread
		if (!ReadStack(0, a)) return Unsupported(ordinal); TerminateCurrentThread(a); break;
	case 260: case 276: case 314: { // ANSI->Unicode / downcase / upcase Unicode
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(a, 8) || !IsRangeValid(b, 8)) return Unsupported(ordinal);
		std::uint16_t sourceLength = 0, destinationMaximum = 0; std::uint32_t source = 0, destination = 0;
		Read(b, sourceLength); Read(b + 4, source); Read(a + 2, destinationMaximum); Read(a + 4, destination);
		const std::uint32_t outputLength = ordinal == 260 ? sourceLength * 2u : sourceLength;
		const std::uint32_t allocationLength = outputLength + (ordinal == 260 ? 2u : 0u);
		if (allocationLength > 0xFFFFu) { m_regs->eax = 0xC00000F0u; FinishStdcall(3); break; }
		if (c) {
			destination = Allocate((std::max)(allocationLength, 1u));
			if (!destination) { m_regs->eax = StatusNoMemory; FinishStdcall(3); break; }
			destinationMaximum = static_cast<std::uint16_t>(allocationLength);
			Write(a + 2, destinationMaximum); Write(a + 4, destination);
		}
		const std::uint32_t required = ordinal == 260 ? allocationLength : outputLength;
		if (!destination || destinationMaximum < required || !IsRangeValid(destination, required) ||
			!IsRangeValid(source, sourceLength)) m_regs->eax = StatusBufferOverflow;
		else {
			for (std::uint32_t i = 0; i < outputLength / 2; ++i) {
				std::uint16_t ch = 0;
				if (ordinal == 260) { std::uint8_t ansi = 0; Read(source + i, ansi); ch = ansi; }
				else Read(source + i * 2, ch);
				if (ordinal == 276) ch = static_cast<std::uint16_t>(std::towlower(ch));
				if (ordinal == 314) ch = static_cast<std::uint16_t>(std::towupper(ch));
				Write(destination + i * 2, ch);
			}
			Write(a, static_cast<std::uint16_t>(outputLength));
			if (ordinal == 260) Write(destination + outputLength, static_cast<std::uint16_t>(0));
			m_regs->eax = StatusSuccess;
		}
		FinishStdcall(3); break;
	}
	case 261: case 262: { // RtlAppendStringToString / UnicodeStringToString
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 8) || !IsRangeValid(b, 8)) return Unsupported(ordinal); std::uint16_t dl = 0, dm = 0, sl = 0; std::uint32_t db = 0, sb = 0;
		Read(a, dl); Read(a + 2, dm); Read(a + 4, db); Read(b, sl); Read(b + 4, sb); if (static_cast<std::uint32_t>(dl) + sl > dm || !CopyGuestMemory(db + dl, sb, sl, true)) m_regs->eax = StatusBufferTooSmall; else { Write(a, static_cast<std::uint16_t>(dl + sl)); m_regs->eax = StatusSuccess; } FinishStdcall(2); break;
	}
	case 263: { // RtlAppendUnicodeToString
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 8)) return Unsupported(ordinal); std::uint32_t bytes = 0; while (IsRangeValid(b + bytes, 2)) { std::uint16_t ch = 0; Read(b + bytes, ch); if (!ch) break; bytes += 2; }
		std::uint16_t dl = 0, dm = 0; std::uint32_t db = 0; Read(a, dl); Read(a + 2, dm); Read(a + 4, db); if (dl + bytes > dm || !CopyGuestMemory(db + dl, b, bytes, true)) m_regs->eax = StatusBufferTooSmall; else { Write(a, static_cast<std::uint16_t>(dl + bytes)); m_regs->eax = StatusSuccess; } FinishStdcall(2); break;
	}
	case 264: // RtlAssert
		if (m_logger) m_logger("[xbox:RtlAssert] guest assertion failed.\r\n"); FinishStdcall(4); break;
	case 265: { // RtlCaptureContext
		std::uint32_t returnAddress = 0; if (!ReadStack(0, a) || !Read(m_regs->esp, returnAddress) || !FillGuestMemory(a, 0, 0x238)) return Unsupported(ordinal); Write(a, 0x00010007u);
		Write(a + 0x208, m_regs->edi); Write(a + 0x20C, m_regs->esi); Write(a + 0x210, m_regs->ebx); Write(a + 0x214, m_regs->edx); Write(a + 0x218, m_regs->ecx); Write(a + 0x21C, m_regs->eax); Write(a + 0x220, m_regs->ebp); Write(a + 0x224, returnAddress); Write(a + 0x228, static_cast<std::uint32_t>(m_regs->cs)); Write(a + 0x22C, m_regs->eflags); Write(a + 0x230, m_regs->esp + 8); Write(a + 0x234, static_cast<std::uint32_t>(m_regs->ss)); FinishStdcall(1); break;
	}
	case 266: case 319: { // RtlCaptureStackBackTrace / RtlWalkFrameChain
		std::uint32_t skip = 0, count = 0, output = 0, hashOut = 0; if (ordinal == 266) { if (!ReadStack(0, skip) || !ReadStack(1, count) || !ReadStack(2, output) || !ReadStack(3, hashOut)) return Unsupported(ordinal); } else { if (!ReadStack(0, output) || !ReadStack(1, count)) return Unsupported(ordinal); }
		std::uint32_t frame = m_regs->ebp, written = 0, hash = 0; while (frame && written < count && IsRangeValid(frame, 8)) { std::uint32_t next = 0, ret = 0; Read(frame, next); Read(frame + 4, ret); if (skip) --skip; else { if (!Write(output + written * 4, ret)) break; hash += ret; ++written; } if (next <= frame) break; frame = next; }
		if (ordinal == 266 && hashOut) Write(hashOut, hash); m_regs->eax = written; FinishStdcall(ordinal == 266 ? 4 : 3); break;
	}
	case 267: case 309: { // RtlCharToInteger / RtlUnicodeStringToInteger
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(c, 4)) return Unsupported(ordinal); std::string text;
		if (ordinal == 267) { for (std::uint32_t p = a; text.size() < 64; ++p) { std::uint8_t ch = 0; if (!Read(p, ch) || !ch) break; text.push_back(static_cast<char>(ch)); } }
		else { std::uint16_t len = 0; std::uint32_t ptr = 0; if (!IsRangeValid(a, 8)) return Unsupported(ordinal); Read(a, len); Read(a + 4, ptr); for (std::uint32_t i = 0; i + 1 < len; i += 2) { std::uint16_t ch = 0; Read(ptr + i, ch); text.push_back(static_cast<char>(ch & 0xFF)); } }
		std::size_t pos = 0; while (pos < text.size() && static_cast<unsigned char>(text[pos]) <= ' ') ++pos;
		bool negative = false; if (pos < text.size() && (text[pos] == '+' || text[pos] == '-')) negative = text[pos++] == '-';
		std::uint32_t base = b;
		if (!base) {
			base = 10;
			if (pos + 1 < text.size() && text[pos] == '0') {
				const char prefix = static_cast<char>(std::tolower(static_cast<unsigned char>(text[pos + 1])));
				if (prefix == 'b') { base = 2; pos += 2; }
				else if (prefix == 'o') { base = 8; pos += 2; }
				else if (prefix == 'x') { base = 16; pos += 2; }
			}
		} else if (base != 2 && base != 8 && base != 10 && base != 16) {
			m_regs->eax = StatusInvalidParameter; FinishStdcall(3); break;
		}
		std::uint32_t value = 0;
		for (; pos < text.size(); ++pos) { char ch = text[pos]; std::uint32_t digit = ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'A' && ch <= 'Z' ? ch - 'A' + 10 : ch >= 'a' && ch <= 'z' ? ch - 'a' + 10 : 0xFFFFFFFFu; if (digit >= base) break; value = value * base + digit; }
		if (negative) value = 0u - value; Write(c, value); m_regs->eax = StatusSuccess; FinishStdcall(3); break;
	}
	case 268: { // RtlCompareMemory
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) ||
			!IsRangeValid(a, c) || !IsRangeValid(b, c)) return Unsupported(ordinal);
		std::uint32_t equal = 0;
		while (equal < c) { std::uint8_t left = 0, right = 0; if (!Read(a + equal, left) || !Read(b + equal, right) || left != right) break; ++equal; }
		m_regs->eax = equal; FinishStdcall(3); break;
	}
	case 269: { // RtlCompareMemoryUlong
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(a, b)) return Unsupported(ordinal);
		std::uint32_t equal = 0, value = 0;
		while (equal + 4 <= b) { if (!Read(a + equal, value) || value != c) break; equal += 4; }
		m_regs->eax = equal; FinishStdcall(3); break;
	}
	case 270: case 271: case 279: case 280: { // Compare/equal ANSI or Unicode strings
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(a, 8) || !IsRangeValid(b, 8)) return Unsupported(ordinal); std::uint16_t al = 0, bl = 0; std::uint32_t ap = 0, bp = 0; Read(a, al); Read(b, bl); Read(a + 4, ap); Read(b + 4, bp); const bool unicode = ordinal == 271 || ordinal == 280; const std::uint32_t unit = unicode ? 2 : 1, count = (std::min)(al, bl) / unit; std::int32_t result = 0;
		for (std::uint32_t i = 0; i < count; ++i) { std::uint16_t ac = 0, bc = 0; if (unicode) { if (!Read(ap + i * 2, ac) || !Read(bp + i * 2, bc)) return Unsupported(ordinal); } else { std::uint8_t ac8 = 0, bc8 = 0; if (!Read(ap + i, ac8) || !Read(bp + i, bc8)) return Unsupported(ordinal); ac = ac8; bc = bc8; } if (c) { ac = unicode ? static_cast<std::uint16_t>(std::towupper(ac)) : static_cast<std::uint8_t>(std::toupper(ac)); bc = unicode ? static_cast<std::uint16_t>(std::towupper(bc)) : static_cast<std::uint8_t>(std::toupper(bc)); } if (ac != bc) { result = ac < bc ? -1 : 1; break; } }
		if (!result && al != bl) result = al < bl ? -1 : 1; m_regs->eax = (ordinal == 279 || ordinal == 280) ? (result == 0 ? 1u : 0u) : static_cast<std::uint32_t>(result); FinishStdcall(3); break;
	}
	case 272: case 273: { // RtlCopyString / RtlCopyUnicodeString
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 8)) return Unsupported(ordinal); std::uint16_t maximum = 0, length = 0; std::uint32_t destination = 0, source = 0; Read(a + 2, maximum); Read(a + 4, destination); if (b) { if (!IsRangeValid(b, 8)) return Unsupported(ordinal); Read(b, length); Read(b + 4, source); length = (std::min)(length, maximum); if (ordinal == 273) length &= ~1u; if (length && !CopyGuestMemory(destination, source, length, true)) return Unsupported(ordinal); } Write(a, length); FinishStdcall(2); break;
	}
	case 274: { // RtlCreateUnicodeString
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 8)) return Unsupported(ordinal); std::uint32_t length = 0; while (IsRangeValid(b + length, 2)) { std::uint16_t ch = 0; Read(b + length, ch); if (!ch) break; length += 2; } const std::uint32_t buffer = Allocate(length + 2); if (!buffer) { FillGuestMemory(a, 0, 8); m_regs->eax = 0; } else if (!CopyGuestMemory(buffer, b, length + 2)) { Free(buffer); FillGuestMemory(a, 0, 8); m_regs->eax = 0; } else { Write(a, static_cast<std::uint16_t>(length)); Write(a + 2, static_cast<std::uint16_t>(length + 2)); Write(a + 4, buffer); m_regs->eax = 1; } FinishStdcall(2); break;
	}
	case 275: case 313: // RtlDowncaseUnicodeChar / RtlUpcaseUnicodeChar
		if (!ReadStack(0, a)) return Unsupported(ordinal); m_regs->eax = ordinal == 275 ? std::towlower(static_cast<wchar_t>(a)) : std::towupper(static_cast<wchar_t>(a)); FinishStdcall(1); break;
	case 277: case 278: { // RtlEnterCriticalSection[/AndRegion]
		if (!ReadStack(0, a) || !IsRangeValid(a, 0x1C)) return Unsupported(ordinal);
		if (ordinal == 278 && m_currentThreadIndex < m_threads.size()) {
			auto& current = m_threads[m_currentThreadIndex];
			if (current.kernelApcDisable > INT_MIN) --current.kernelApcDisable;
			Write(current.guestThread + 0x68, static_cast<std::uint32_t>(current.kernelApcDisable));
		}
		std::int32_t lockCount = -1, recursionCount = 0;
		std::uint32_t owner = 0;
		Read(a + 0x10, lockCount); Read(a + 0x14, recursionCount); Read(a + 0x18, owner);
		++lockCount;
		Write(a + 0x10, lockCount);
		// Match the legacy routine exactly: an ownerless statically initialized
		// section is acquired immediately even when its LockCount is already zero.
		// Waiting in that state loses the only possible wake-up and deadlocks.
		if (lockCount == 0 || owner == 0 || owner == m_currentThread) {
			Write(a + 0x14, owner == m_currentThread ? recursionCount + 1 : 1);
			Write(a + 0x18, m_currentThread);
			FinishStdcall(1);
			break;
		}

		auto object = GetDispatcherObject(a);
		if (!object) {
			// Some titles use a statically initialized critical section. Its
			// dispatcher header is already guest memory, so only register the
			// backing synchronization object here.
			object = std::make_shared<KernelObject>();
			object->kind = ObjectKind::Event;
			object->manualReset = false;
			object->guestAddress = a;
			std::lock_guard<std::mutex> lock(m_objectMutex);
			m_dispatcherObjects[a] = object;
		}
		FinishStdcall(1);
		m_threads[m_currentThreadIndex].criticalSectionWait = a;
		ScheduleWait({ object }, false, false, 0);
		break;
	}
	case 281: { // RtlExtendedIntegerMultiply
		std::uint32_t low = 0, high = 0; if (!ReadStack(0, low) || !ReadStack(1, high) || !ReadStack(2, a)) return Unsupported(ordinal); const std::int64_t value = static_cast<std::int64_t>((static_cast<std::uint64_t>(high) << 32) | low) * static_cast<std::int32_t>(a); SetReturn64(static_cast<std::uint64_t>(value)); FinishStdcall(3); break;
	}
	case 282: { // RtlExtendedLargeIntegerDivide
		std::uint32_t low = 0, high = 0, divisor = 0, remainder = 0; if (!ReadStack(0, low) || !ReadStack(1, high) || !ReadStack(2, divisor) || !ReadStack(3, remainder)) return Unsupported(ordinal); if (!divisor) { RaiseGuestException(0xC0000094u, 4, "RtlExtendedLargeIntegerDivide"); break; } const std::uint64_t dividend = (static_cast<std::uint64_t>(high) << 32) | low; if (remainder) Write(remainder, static_cast<std::uint32_t>(dividend % divisor)); SetReturn64(dividend / divisor); FinishStdcall(4); break;
	}
	case 283: { // RtlExtendedMagicDivide
		std::uint32_t dl = 0, dh = 0, ml = 0, mh = 0, shift = 0; if (!ReadStack(0, dl) || !ReadStack(1, dh) || !ReadStack(2, ml) || !ReadStack(3, mh) || !ReadStack(4, shift)) return Unsupported(ordinal); const std::int64_t dividend = static_cast<std::int64_t>((static_cast<std::uint64_t>(dh) << 32) | dl); const std::uint64_t magic = (static_cast<std::uint64_t>(mh) << 32) | ml; const bool negative = dividend < 0; const std::uint64_t magnitude = negative ? 0u - static_cast<std::uint64_t>(dividend) : static_cast<std::uint64_t>(dividend); const std::uint64_t ah = magnitude >> 32, al = magnitude & 0xFFFFFFFFu, bh = magic >> 32, bl = magic & 0xFFFFFFFFu, ahbl = ah * bl, albh = al * bh; std::uint64_t result = (ah * bh + (ahbl >> 32) + (albh >> 32) + (((ahbl & 0xFFFFFFFFu) + (albh & 0xFFFFFFFFu) + ((al * bl) >> 32)) >> 32)) >> (shift & 63); SetReturn64(negative ? 0u - result : result); FinishStdcall(5); break;
	}
	case 284: // RtlFillMemory
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(a, b)) return Unsupported(ordinal);
		FillGuestMemory(a, static_cast<std::uint8_t>(c), b); FinishStdcall(3); break;
	case 285: // RtlFillMemoryUlong
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(a, b)) return Unsupported(ordinal);
		for (std::uint32_t offset = 0; offset + 4 <= b; offset += 4) Write(a + offset, c);
		FinishStdcall(3); break;
	case 286: case 287: // RtlFreeAnsiString / RtlFreeUnicodeString
		if (!ReadStack(0, a) || !IsRangeValid(a, 8)) return Unsupported(ordinal); Read(a + 4, b); if (b) Free(b); FillGuestMemory(a, 0, 8); FinishStdcall(1); break;
	case 288: // RtlGetCallersAddress
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal); { std::uint32_t frame = m_regs->ebp, caller = 0, callersCaller = 0, next = 0; if (IsRangeValid(frame, 8)) { Read(frame + 4, caller); Read(frame, next); if (IsRangeValid(next, 8)) Read(next + 4, callersCaller); } if (a) Write(a, caller); if (b) Write(b, callersCaller); } FinishStdcall(2); break;
	case 289: case 290: { // RtlInitAnsiString / RtlInitUnicodeString
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 8)) return Unsupported(ordinal);
		std::uint16_t length = 0;
		if (b) {
			const std::uint32_t unit = ordinal == 289 ? 1 : 2;
			while (length <= 0xFFFC && IsRangeValid(b + length, unit)) {
				std::uint16_t ch = 0;
				if (unit == 1) { std::uint8_t byte = 0; if (!Read(b + length, byte)) break; ch = byte; }
				else if (!Read(b + length, ch)) break;
				if (!ch) break;
				length = static_cast<std::uint16_t>(length + unit);
			}
		}
		const std::uint16_t maximum = b ? static_cast<std::uint16_t>(length + (ordinal == 289 ? 1 : 2)) : 0;
		Write(a, length); Write(a + 2, maximum); Write(a + 4, b); FinishStdcall(2); break;
	}
	case 291: { // RtlInitializeCriticalSection
		if (!ReadStack(0, a) || !IsRangeValid(a, 0x1C)) return Unsupported(ordinal);
		auto object = std::make_shared<KernelObject>();
		object->kind = ObjectKind::Event;
		object->manualReset = false;
		object->signaled = false;
		object->guestAddress = a;
		InitializeDispatcher(a, 1, 0);
		Write(a + 0x10, static_cast<std::int32_t>(-1));
		Write(a + 0x14, 0u); Write(a + 0x18, 0u);
		{ std::lock_guard<std::mutex> lock(m_objectMutex); m_dispatcherObjects[a] = object; }
		FinishStdcall(1); break;
	}
	case 292: case 293: { // RtlIntegerToChar / RtlIntegerToUnicodeString
		if (!ReadStack(0, a) || !ReadStack(1, b)) return Unsupported(ordinal); if (b == 0) b = 10; if (b != 2 && b != 8 && b != 10 && b != 16) { m_regs->eax = StatusInvalidParameter; FinishStdcall(ordinal == 292 ? 4 : 3); break; } char digits[34] = {}; std::uint32_t value = a, length = 0; do { const std::uint32_t digit = value % b; digits[length++] = static_cast<char>(digit < 10 ? '0' + digit : 'A' + digit - 10); value /= b; } while (value && length < 33); std::reverse(digits, digits + length);
		if (ordinal == 292) { if (!ReadStack(2, c) || !ReadStack(3, d)) return Unsupported(ordinal); if (c < length) m_regs->eax = StatusBufferOverflow; else if (!d || !IsRangeValid(d, c)) return Unsupported(ordinal); else { auto* output = GuestPointer(d, c); std::memcpy(output, digits, length); if (static_cast<std::uint32_t>(c) > length) output[length] = 0; m_regs->eax = StatusSuccess; } FinishStdcall(4); }
		else { if (!ReadStack(2, c) || !IsRangeValid(c, 8)) return Unsupported(ordinal); std::uint16_t maximum = 0; std::uint32_t buffer = 0; Read(c + 2, maximum); Read(c + 4, buffer); const std::uint32_t required = length * 2 + 2; if (maximum < required) m_regs->eax = StatusBufferOverflow; else if (!IsRangeValid(buffer, required)) return Unsupported(ordinal); else { for (std::uint32_t i = 0; i < length; ++i) Write(buffer + i * 2, static_cast<std::uint16_t>(digits[i])); Write(c, static_cast<std::uint16_t>(length * 2)); Write(buffer + length * 2, static_cast<std::uint16_t>(0)); m_regs->eax = StatusSuccess; } FinishStdcall(3); } break;
	}
	case 294: case 295: { // RtlLeaveCriticalSection[/AndRegion]
		if (!ReadStack(0, a) || !IsRangeValid(a, 0x1C)) return Unsupported(ordinal);
		std::int32_t lockCount = -1, recursionCount = 0;
		std::uint32_t owner = 0;
		Read(a + 0x10, lockCount); Read(a + 0x14, recursionCount); Read(a + 0x18, owner);
		if (owner != m_currentThread || recursionCount <= 0) {
			if (m_logger) m_logger("[uwp-kernel:error] RtlLeaveCriticalSection sem posse da thread atual.\r\n");
			FinishStdcall(1); break;
		}
		--recursionCount; --lockCount;
		Write(a + 0x10, lockCount); Write(a + 0x14, recursionCount);
		if (recursionCount == 0) {
			Write(a + 0x18, 0u);
			if (lockCount >= 0) {
				auto object = GetDispatcherObject(a);
				if (object) {
					std::lock_guard<std::mutex> lock(m_objectMutex);
					object->signaled = true;
					SyncDispatcherSignal(object);
					m_objectChanged.notify_all();
				}
			}
		}
		const bool leaveRegion = ordinal == 295 && recursionCount == 0 && m_currentThreadIndex < m_threads.size();
		if (leaveRegion) {
			auto& current = m_threads[m_currentThreadIndex];
			if (current.kernelApcDisable < 0) ++current.kernelApcDisable;
			Write(current.guestThread + 0x68, static_cast<std::uint32_t>(current.kernelApcDisable));
		}
		FinishStdcall(1);
		if (recursionCount == 0 && lockCount >= 0) { WakeThreads(); SyncReadyList(); }
		if (leaveRegion && m_threads[m_currentThreadIndex].kernelApcDisable == 0)
			DeliverPendingApc(m_threads[m_currentThreadIndex]);
		break;
	}
	case 296: case 316: // RtlLowerChar / RtlUpperChar
		if (!ReadStack(0, a)) return Unsupported(ordinal); {
			std::uint8_t character = static_cast<std::uint8_t>(a);
			if (ordinal == 296) {
				if ((character >= 'A' && character <= 'Z') || (character >= 0xC0 && character <= 0xDE && character != 0xD7)) character ^= 0x20;
			} else {
				if ((character >= 'a' && character <= 'z') || (character >= 0xE0 && character <= 0xFE && character != 0xF7)) character ^= 0x20;
				else if (character == 0xFF) character = '?';
			}
			m_regs->eax = character;
		}
		FinishStdcall(1); break;
	case 297: { // RtlMapGenericMask
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 4) || !IsRangeValid(b, 16)) return Unsupported(ordinal); std::uint32_t mask = 0, mapped = 0; Read(a, mask); if (mask & 0x80000000u) { Read(b, c); mapped |= c; } if (mask & 0x40000000u) { Read(b + 4, c); mapped |= c; } if (mask & 0x20000000u) { Read(b + 8, c); mapped |= c; } if (mask & 0x10000000u) { Read(b + 12, c); mapped |= c; } mask = (mask & 0x0FFFFFFFu) | mapped; Write(a, mask); FinishStdcall(2); break;
	}
	case 298: // RtlMoveMemory
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(a, c) || !IsRangeValid(b, c)) return Unsupported(ordinal);
		CopyGuestMemory(a, b, c, true); FinishStdcall(3); break;
	case 299: case 310: case 315: { // MultiByte/Unicode conversions
		std::uint32_t maximum = 0, writtenOut = 0, source = 0, sourceBytes = 0; if (!ReadStack(0, a) || !ReadStack(1, maximum) || !ReadStack(2, writtenOut) || !ReadStack(3, source) || !ReadStack(4, sourceBytes)) return Unsupported(ordinal); const bool toUnicode = ordinal == 299; const std::uint32_t units = toUnicode ? (std::min)(maximum / 2, sourceBytes) : (std::min)(maximum, sourceBytes / 2); if (!IsRangeValid(a, units * (toUnicode ? 2 : 1)) || !IsRangeValid(source, units * (toUnicode ? 1 : 2))) return Unsupported(ordinal); for (std::uint32_t i = 0; i < units; ++i) { if (toUnicode) { std::uint8_t ch = 0; Read(source + i, ch); Write(a + i * 2, static_cast<std::uint16_t>(ch)); } else { std::uint16_t ch = 0; Read(source + i * 2, ch); if (ordinal == 315) ch = static_cast<std::uint16_t>(std::towupper(ch)); Write(a + i, static_cast<std::uint8_t>(ch <= 0xFF ? ch : '?')); } } if (writtenOut) Write(writtenOut, units * (toUnicode ? 2u : 1u)); m_regs->eax = StatusSuccess; FinishStdcall(5); break;
	}
	case 300: case 311: // MultiByte/Unicode size
		if (!ReadStack(0, a) || !ReadStack(2, b) || !IsRangeValid(a, 4)) return Unsupported(ordinal); Write(a, ordinal == 300 ? b * 2 : b / 2); m_regs->eax = StatusSuccess; FinishStdcall(3); break;
	case 301: // RtlNtStatusToDosError
		if (!ReadStack(0, a)) return Unsupported(ordinal);
		switch (a) {
		case StatusSuccess: m_regs->eax = ERROR_SUCCESS; break;
		case StatusInvalidHandle: m_regs->eax = ERROR_INVALID_HANDLE; break;
		case StatusInvalidParameter: m_regs->eax = ERROR_INVALID_PARAMETER; break;
		case StatusAccessDenied: m_regs->eax = ERROR_ACCESS_DENIED; break;
		case StatusObjectNameNotFound: m_regs->eax = ERROR_FILE_NOT_FOUND; break;
		case StatusObjectNameCollision: m_regs->eax = ERROR_ALREADY_EXISTS; break;
		case StatusEndOfFile: m_regs->eax = ERROR_HANDLE_EOF; break;
		case StatusBufferTooSmall: m_regs->eax = ERROR_INSUFFICIENT_BUFFER; break;
		case StatusCancelled: m_regs->eax = ERROR_OPERATION_ABORTED; break;
		case StatusNotImplemented: m_regs->eax = ERROR_CALL_NOT_IMPLEMENTED; break;
		case StatusTimeout: m_regs->eax = ERROR_TIMEOUT; break;
		case StatusInvalidDeviceRequest: m_regs->eax = ERROR_INVALID_FUNCTION; break;
		case StatusNoMoreFiles: m_regs->eax = ERROR_NO_MORE_FILES; break;
		default: m_regs->eax = ERROR_MR_MID_NOT_FOUND; break;
		}
		FinishStdcall(1); break;
	case 304: { // RtlTimeFieldsToTime
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 16) || !IsRangeValid(b, 8)) return Unsupported(ordinal); SYSTEMTIME st = {}; Read(a, st.wYear); Read(a + 2, st.wMonth); Read(a + 4, st.wDay); Read(a + 6, st.wHour); Read(a + 8, st.wMinute); Read(a + 10, st.wSecond); Read(a + 12, st.wMilliseconds); FILETIME ft = {}; if (SystemTimeToFileTime(&st, &ft)) { const std::uint64_t value = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime; Write(b, value); m_regs->eax = 1; } else m_regs->eax = 0; FinishStdcall(2); break;
	}
	case 305: { // RtlTimeToTimeFields
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 8) || !IsRangeValid(b, 16)) return Unsupported(ordinal); std::uint64_t value = 0; Read(a, value); FILETIME ft = { static_cast<DWORD>(value), static_cast<DWORD>(value >> 32) }; SYSTEMTIME st = {}; if (!FileTimeToSystemTime(&ft, &st)) std::memset(&st, 0, sizeof(st)); Write(b, st.wYear); Write(b + 2, st.wMonth); Write(b + 4, st.wDay); Write(b + 6, st.wHour); Write(b + 8, st.wMinute); Write(b + 10, st.wSecond); Write(b + 12, st.wMilliseconds); Write(b + 14, st.wDayOfWeek); FinishStdcall(2); break;
	}
	case 306: { // RtlTryEnterCriticalSection
		if (!ReadStack(0, a) || !IsRangeValid(a, 0x1C)) return Unsupported(ordinal);
		std::int32_t lockCount = -1, recursionCount = 0;
		std::uint32_t owner = 0;
		Read(a + 0x10, lockCount); Read(a + 0x14, recursionCount); Read(a + 0x18, owner);
		if (lockCount == -1) {
			Write(a + 0x10, 0); Write(a + 0x14, 1u); Write(a + 0x18, m_currentThread);
			m_regs->eax = 1;
		} else if (owner == m_currentThread) {
			Write(a + 0x10, lockCount + 1); Write(a + 0x14, recursionCount + 1);
			m_regs->eax = 1;
		} else m_regs->eax = 0;
		FinishStdcall(1); break;
	}
	case 308: { // RtlUnicodeStringToAnsiString
		if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, c) || !IsRangeValid(a, 8) || !IsRangeValid(b, 8)) return Unsupported(ordinal);
		std::uint16_t sl = 0, dm = 0; std::uint32_t sp = 0, dp = 0;
		Read(b, sl); Read(b + 4, sp); const std::uint32_t length = sl / 2; const std::uint32_t required = length + 1;
		Read(a + 2, dm); Read(a + 4, dp); Write(a, static_cast<std::uint16_t>(length));
		if (c) {
			dp = Allocate(required); dm = static_cast<std::uint16_t>(required);
			Write(a + 2, dm); Write(a + 4, dp);
			if (!dp) { m_regs->eax = StatusNoMemory; FinishStdcall(3); break; }
		}
		std::uint32_t copyLength = length;
		std::uint32_t status = StatusSuccess;
		if (dm < required) {
			status = StatusBufferOverflow;
			if (!dm) { m_regs->eax = status; FinishStdcall(3); break; }
			copyLength = dm - 1; Write(a, static_cast<std::uint16_t>(copyLength));
		}
		if (!dp || !IsRangeValid(dp, copyLength + 1) || !IsRangeValid(sp, sl)) return Unsupported(ordinal);
		for (std::uint32_t i = 0; i < copyLength; ++i) { std::uint16_t ch = 0; Read(sp + i * 2, ch); Write(dp + i, static_cast<std::uint8_t>(ch <= 0xFF ? ch : '?')); }
		Write(dp + copyLength, static_cast<std::uint8_t>(0)); m_regs->eax = status; FinishStdcall(3); break;
	}
	case 312: { // RtlUnwind
		std::uint32_t record = 0; if (!ReadStack(0, a) || !ReadStack(1, b) || !ReadStack(2, record) || !ReadStack(3, c)) return Unsupported(ordinal);
		FinishStdcall(4); m_unwindResume = *m_regs; m_unwindTargetFrame = a; m_unwindTargetIp = b; m_unwindReturnValue = c;
		m_unwindRecord = record; m_unwindOwnRecord = record == 0; if (!m_unwindRecord) m_unwindRecord = Allocate(80);
		m_unwindContext = Allocate(0x238); m_unwindDispatcherContext = Allocate(4);
		if (!m_unwindRecord || !m_unwindContext || !m_unwindDispatcherContext) { if (m_unwindOwnRecord && m_unwindRecord) Free(m_unwindRecord); if (m_unwindContext) Free(m_unwindContext); if (m_unwindDispatcherContext) Free(m_unwindDispatcherContext); m_unwindRecord = m_unwindContext = m_unwindDispatcherContext = 0; m_regs->eax = StatusNoMemory; cpu_exit(m_cpu); break; }
		if (m_unwindOwnRecord) { FillGuestMemory(m_unwindRecord, 0, 80); Write(m_unwindRecord, 0xC0000027u); }
		std::uint32_t flags = 0; Read(m_unwindRecord + 4, flags); flags |= 2u; if (!a) flags |= 4u; Write(m_unwindRecord + 4, flags);
		FillGuestMemory(m_unwindContext, 0, 0x238); Write(m_unwindContext, 0x00010007u);
		Write(m_unwindContext + 0x208, m_unwindResume.edi); Write(m_unwindContext + 0x20C, m_unwindResume.esi);
		Write(m_unwindContext + 0x210, m_unwindResume.ebx); Write(m_unwindContext + 0x214, m_unwindResume.edx);
		Write(m_unwindContext + 0x218, m_unwindResume.ecx); Write(m_unwindContext + 0x21C, m_unwindResume.eax);
		Write(m_unwindContext + 0x220, m_unwindResume.ebp); Write(m_unwindContext + 0x224, m_unwindResume.eip);
		Write(m_unwindContext + 0x228, static_cast<std::uint32_t>(m_unwindResume.cs)); Write(m_unwindContext + 0x22C, m_unwindResume.eflags);
		Write(m_unwindContext + 0x230, m_unwindResume.esp); Write(m_unwindContext + 0x234, static_cast<std::uint32_t>(m_unwindResume.ss));
		m_unwindRegistration = 0xFFFFFFFFu; if (m_regs->fs_hidden.base) Read(m_regs->fs_hidden.base, m_unwindRegistration);
		m_unwindActive = true; DeliverNextUnwindHandler(); break;
	}
	case 317: { // RtlUpperString
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, 8) || !IsRangeValid(b, 8)) return Unsupported(ordinal); std::uint16_t sl = 0, dm = 0; std::uint32_t sp = 0, dp = 0; Read(b, sl); Read(b + 4, sp); Read(a + 2, dm); Read(a + 4, dp); const std::uint16_t length = (std::min)(sl, dm); if (!IsRangeValid(sp, length) || !IsRangeValid(dp, length)) return Unsupported(ordinal); for (std::uint32_t i = 0; i < length; ++i) { std::uint8_t ch = 0; Read(sp + i, ch); if ((ch >= 'a' && ch <= 'z') || (ch >= 0xE0 && ch <= 0xFE && ch != 0xF7)) ch ^= 0x20; else if (ch == 0xFF) ch = '?'; Write(dp + i, ch); } Write(a, length); FinishStdcall(2); break;
	}
	case 307: // RtlUlongByteSwap, fastcall
		a = m_regs->ecx; m_regs->eax = _byteswap_ulong(a); FinishFastcall(); break;
	case 318: // RtlUshortByteSwap, fastcall
		a = m_regs->ecx; m_regs->eax = _byteswap_ushort(static_cast<unsigned short>(a)); FinishFastcall(); break;
	case 320: // RtlZeroMemory
		if (!ReadStack(0, a) || !ReadStack(1, b) || !IsRangeValid(a, b)) return Unsupported(ordinal);
		FillGuestMemory(a, 0, b); FinishStdcall(2); break;
	default:
		Unsupported(ordinal); break;
	}
}
