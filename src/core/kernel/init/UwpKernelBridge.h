#pragma once

#include "UwpDeviceInterrupts.h"
#include <lib86cpu.hpp>
#include <Windows.h>

#include <cstddef>
#include <atomic>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class CxbxUwpXisoReader;

class CxbxUwpKernelBridge final
{
public:
	using LogCallback = void(*)(const char* text);

	CxbxUwpKernelBridge(cpu_t* cpu, std::uint8_t* ram, LogCallback logger,
		const wchar_t* dataRoot = nullptr, const wchar_t* gameRoot = nullptr,
		std::uint32_t titleId = 0, const wchar_t* gamePath = nullptr,
		bool gameIsXiso = false, std::uint64_t gameImageOffset = 0,
		const std::uint8_t* certificateLanKey = nullptr,
		const std::uint8_t* certificateSignatureKey = nullptr,
		const std::uint8_t* certificateAlternateKeys = nullptr,
		std::uint8_t* kernelVirtualMemory = nullptr,
		std::size_t kernelVirtualMemorySize = 0);
	~CxbxUwpKernelBridge();
	CxbxUwpKernelBridge(const CxbxUwpKernelBridge&) = delete;
	CxbxUwpKernelBridge& operator=(const CxbxUwpKernelBridge&) = delete;

	HRESULT Install(std::uint32_t encodedThunkAddress, std::uint32_t consoleType,
		std::uint32_t imageEndAddress);
	HRESULT InitializeTls(std::uint32_t tlsDirectoryAddress, std::uint32_t stackBase);
	void RequestStop();
	void RequestInterrupt(std::uint32_t busInterruptLevel);
	void AssertInterrupt(std::uint32_t busInterruptLevel, std::uint32_t sourceMask);
	void AcknowledgeInterrupt(std::uint32_t busInterruptLevel, std::uint32_t sourceMask);
	void OnTimeslice();
	void Dispatch(std::uint32_t ordinal);
	bool TakeRebootRequest(std::wstring& hostPath, std::string& xisoEntry,
		std::array<std::uint8_t, 4096>& launchData);
	void RestoreLaunchData(const std::uint8_t* launchData, std::size_t size);

private:
	enum class ObjectKind { File, Directory, Event, Semaphore, Timer, Mutant, Thread, Queue, IoCompletion, SymbolicLink };
	struct KernelObject;
	using ObjectPtr = std::shared_ptr<KernelObject>;
	struct ApcItem { std::uint32_t address, kernelRoutine, rundownRoutine, normalRoutine, context, argument1, argument2; bool userMode; };
	struct DpcItem { std::uint32_t address, routine, context, argument1, argument2; };
	struct InterruptItem
	{
		std::uint32_t address = 0, routine = 0, context = 0;
		std::uint32_t busLevel = 0, irql = 0, mode = 0;
		bool connected = false;
		bool pulsePending = false;
		bool inService = false;
		std::uint32_t assertedSources = 0;
	};
	struct InterruptFrame
	{
		regs_t resume = {};
		std::uint32_t address = 0, level = 0;
		std::uint8_t irql = 0;
		bool active = false;
	};
	struct DriverFrame
	{
		regs_t resume = {};
		std::uint32_t irp = 0, informationOut = 0;
		ObjectPtr waitEvent;
		bool returnsStatus = false, freeIrp = false;
	};
	struct ThreadNotifyItem { std::uint32_t routine, thread, threadId; bool create; };
	enum class ThreadState { Running, Runnable, Waiting, Sleeping, Suspended, Terminated };
	struct ThreadContext
	{
		std::uint32_t id = 0;
		std::uint32_t uniqueThread = 0;
		std::uint32_t guestThread = 0;
		std::int8_t basePriority = 8;
		std::int8_t priority = 8;
		std::uint32_t quantumRemaining = 60;
		std::uint32_t suspendCount = 0;
		regs_t regs = {};
		ThreadState state = ThreadState::Runnable;
		std::vector<ObjectPtr> waitObjects;
		std::vector<std::uint32_t> waitBlocks;
		bool ownsWaitBlocks = true;
		bool ownsWaitReferences = false;
		std::uint32_t criticalSectionWait = 0;
		std::uint32_t queueWait = 0;
		std::uint32_t associatedQueue = 0;
		std::uint32_t completionKeyOut = 0;
		std::uint32_t completionApcOut = 0;
		std::uint32_t completionIosbOut = 0;
		std::array<bool, 2> alerted = {};
		bool waitAll = false;
		bool alertable = false;
		std::uint8_t waitMode = 0;
		bool infiniteWait = true;
		std::chrono::steady_clock::time_point deadline = {};
		std::vector<ApcItem> apcs;
		regs_t apcResume = {};
		ApcItem activeApc = {};
		std::uint32_t apcScratch = 0;
		std::uint8_t apcStage = 0;
		std::uint8_t apcSavedIrql = 0;
		bool deliveringApc = false;
		bool userApcDeliveryPending = false;
		bool terminatingApcRundown = false;
		std::int32_t kernelApcDisable = 0;
		std::uint32_t exitStatus = 0;
		std::uint32_t stackAllocation = 0;
		std::uint32_t tib = 0, tlsVector = 0, tlsData = 0;
		std::uint32_t exceptionList = 0xFFFFFFFFu;
		regs_t tlsResume = {};
		std::size_t tlsCallbackIndex = 0;
		std::uint32_t tlsCallbackReason = 0;
		bool tlsCallbacksActive = false;
		bool tlsDetached = false;
		bool terminateAfterTls = false;
		bool resumeWaitAfterApc = false;
		ThreadState apcInterruptedState = ThreadState::Waiting;
		std::uint32_t pendingIrp = 0;
		std::uint32_t pendingIrpInformationOut = 0;
		bool freePendingIrp = false;
	};

	bool IsRangeValid(std::uint32_t address, std::size_t size) const;
	std::uint8_t* GuestPointer(std::uint32_t address, std::size_t size);
	const std::uint8_t* GuestPointer(std::uint32_t address, std::size_t size) const;
	bool FillGuestMemory(std::uint32_t address, std::uint8_t value, std::size_t size);
	bool CopyGuestMemory(std::uint32_t destination, std::uint32_t source,
		std::size_t size, bool allowOverlap = false);
	template<typename T> bool Read(std::uint32_t address, T& value) const;
	template<typename T> bool Write(std::uint32_t address, const T& value);
	bool ReadStack(std::uint32_t index, std::uint32_t& value) const;
	void FinishStdcall(std::uint32_t argumentCount);
	void FinishCdecl();
	void FinishFastcall(std::uint32_t stackArgumentCount = 0);
	int FormatGuestString(std::uint32_t formatAddress, std::uint32_t argumentsAddress,
		std::string& result);
	void SetReturn64(std::uint64_t value);
	std::uint32_t Allocate(std::uint32_t size);
	std::uint32_t AllocateAligned(std::uint32_t size, std::uint32_t alignment,
		std::uint32_t lowest, std::uint32_t highest, std::uint32_t protect = PAGE_READWRITE);
	void Free(std::uint32_t address);
	std::uint32_t AllocationSize(std::uint32_t address) const;
	bool IsAddressMapped(std::uint32_t address) const;
	bool FindAllocation(std::uint32_t address, std::uint32_t& base, std::uint32_t& size) const;
	void SetPageRange(std::uint32_t address, std::uint32_t size,
		std::uint32_t state, std::uint32_t protect);
	std::uint32_t CreateHandle(ObjectPtr object);
	std::uint32_t CreateOutputHandle(const ObjectPtr& object, std::uint32_t handleOut);
	std::uint32_t CreateNamedHandle(const ObjectPtr& object, std::uint32_t attributes,
		std::uint32_t handleOut);
	bool EnsureGuestObjectBody(const ObjectPtr& object);
	ObjectPtr GetHandle(std::uint32_t handle) const;
	ObjectPtr GetDispatcherObject(std::uint32_t address);
	std::uint32_t CloseGuestHandle(std::uint32_t handle);
	void DereferenceObject(const ObjectPtr& object, bool decrement);
	bool ReadObjectName(std::uint32_t attributesAddress, std::wstring& name,
		std::uint32_t& rootHandle) const;
	std::uint32_t ResolveObjectName(std::uint32_t attributesAddress,
		std::wstring& name, ObjectPtr* parent = nullptr) const;
	bool ResolveGuestPath(std::uint32_t attributesAddress, std::wstring& path) const;
	bool GetXisoRelativePath(const std::wstring& path, std::string& relative) const;
	std::uint32_t OpenGuestFile(std::uint32_t handleOut, std::uint32_t desiredAccess,
		std::uint32_t attributes, std::uint32_t ioStatus, std::uint32_t shareAccess,
		std::uint32_t disposition, std::uint32_t options);
	void WriteIoStatus(std::uint32_t address, std::uint32_t status,
		std::uint32_t information);
	void SignalFileCompletion(const ObjectPtr& object, std::uint32_t status);
	void CompleteIrp(std::uint32_t irp);
	std::uint32_t StatusFromWin32(std::uint32_t error) const;
	std::chrono::steady_clock::time_point DecodeDeadline(std::uint32_t timeoutAddress,
		bool& infinite) const;
	void ExpireTimer(const ObjectPtr& object, std::chrono::steady_clock::time_point now);
	bool TrySatisfy(const ObjectPtr& object, ThreadContext* acquiringThread = nullptr);
	std::uint32_t PulseEventObject(const ObjectPtr& object);
	std::uint32_t WaitObjects(const std::vector<ObjectPtr>& objects, bool waitAll,
		std::uint32_t timeoutAddress);
	void InitializeDispatcher(std::uint32_t address, std::uint8_t type,
		std::int32_t signalState);
	void InitializeGuestThreadBody(std::uint32_t address);
	void LinkMutantToThread(const ObjectPtr& object, ThreadContext* thread);
	void UnlinkMutant(const ObjectPtr& object);
	void SyncDispatcherSignal(const ObjectPtr& object);
	HRESULT InitializeThreadTls(regs_t& registers, std::uint32_t stackBase,
		std::uint32_t& pcr, std::uint32_t& tlsVector, std::uint32_t& tlsData,
		std::uint32_t stackSize = 0x100000, std::uint32_t requestedTlsDataSize = 0);
	void SyncProcessorControlRegion(ThreadContext& thread);
	void SetCurrentIrql(std::uint8_t irql);
	bool StartTlsCallbacks(ThreadContext& thread, std::uint32_t reason);
	bool ContinueTlsCallbacks(ThreadContext& thread);
	std::uint32_t CreateGuestThread(std::uint32_t startRoutine, std::uint32_t startContext,
		std::uint32_t systemRoutine, std::uint32_t stackSize, bool suspended,
		std::uint32_t handleOut, std::uint32_t threadIdOut,
		std::uint32_t threadExtensionSize = 0, std::uint32_t tlsDataSize = 0);
	void WakeThreads();
	bool LinkWaitBlocks(ThreadContext& thread, std::uint32_t waitBlockArray = 0);
	void UnlinkWaitBlocks(ThreadContext& thread);
	void SyncReadyList();
	bool SwitchThread(bool makeCurrentRunnable);
	void ScheduleDelay(std::uint32_t timeoutAddress, bool alertable,
		std::uint8_t waitMode = 0, std::uint8_t waitReason = 4);
	void ScheduleWait(std::vector<ObjectPtr> objects, bool waitAll, bool alertable,
		std::uint32_t timeoutAddress, std::uint8_t waitMode = 0,
		std::uint8_t waitReason = 0, std::uint32_t waitBlockArray = 0);
	bool DeliverPendingApc(ThreadContext& thread);
	bool QueueDpc(std::uint32_t address, std::uint32_t argument1, std::uint32_t argument2);
	bool DeliverPendingDpc();
	bool DeliverPendingInterrupt();
	ThreadContext* FindThreadByGuestAddress(std::uint32_t address);
	ThreadContext* FindThreadByHandle(std::uint32_t handle);
	void TerminateCurrentThread(std::uint32_t status);
	void QueueThreadNotifications(std::uint32_t thread, std::uint32_t threadId, bool create);
	bool DeliverThreadNotification();
	bool StartShutdownNotifications(bool terminateAfter);
	bool ContinueShutdownNotifications();
	void RaiseGuestException(std::uint32_t code, std::uint32_t argumentCount,
		const char* source, std::uint32_t sourceRecord = 0,
		std::uint32_t exceptionFlags = 0, std::uint32_t exceptionAddress = 0);
	bool DeliverNextExceptionHandler();
	bool DeliverNextUnwindHandler();
	void InitializeExportedData(bool debugXbe);
	void UpdateExportedData();
	void SyncExportedHandleTable();
	void Unsupported(std::uint32_t ordinal);
	void LogOrdinal(const char* operation, std::uint32_t ordinal) const;
	void LogUnknownControl(bool deviceControl, std::uint32_t code,
		std::uint32_t input, std::uint32_t inputLength, std::uint32_t outputLength,
		const ObjectPtr& object);

	cpu_t* m_cpu;
	std::uint8_t* m_ram;
	std::uint8_t* m_kernelVirtualMemory;
	std::size_t m_kernelVirtualMemorySize;
	regs_t* m_regs;
	LogCallback m_logger;
	std::wstring m_dataRoot;
	std::wstring m_gameRoot;
	std::wstring m_gamePath;
	std::unique_ptr<CxbxUwpXisoReader> m_xiso;
	std::uint64_t m_gameImageOffset = 0;
	std::uint32_t m_titleId = 0;
	std::array<std::uint8_t, 16> m_certificateLanKey = {};
	std::array<std::uint8_t, 16> m_certificateSignatureKey = {};
	std::array<std::uint8_t, 16 * 16> m_certificateAlternateKeys = {};
	std::int64_t m_systemTimeOffset = 0;
	std::chrono::steady_clock::time_point m_kernelBootTime = std::chrono::steady_clock::now();
	std::uint64_t m_lastExportedTick = 0;
	std::uint32_t m_poolCursor = 0;
	std::uint32_t m_poolLimit = 0;
	std::uint32_t m_imageEndAddress = 0;
	std::uint32_t m_gpuInstanceMemoryBytes = 0x10000;
	std::uint32_t m_avSavedDataAddress = 0;
	std::uint32_t m_avCurrentMode = 0;
	std::unordered_map<std::uint32_t, std::uint32_t> m_allocations;
	std::map<std::uint32_t, std::uint32_t> m_freeAllocations;
	std::unordered_map<std::uint32_t, std::uint32_t> m_allocationProtect;
	std::unordered_map<std::uint32_t, std::uint32_t> m_pageState;
	std::unordered_map<std::uint32_t, std::uint32_t> m_pageProtect;
	std::unordered_map<std::uint32_t, std::uint32_t> m_pageLockCount;
	std::unordered_map<std::uint32_t, std::pair<std::uint32_t, std::uint32_t>> m_ioMappings;
	std::unordered_map<std::uint32_t, std::uint32_t> m_kernelStacks;
	std::unordered_map<std::uint32_t, bool> m_persistedAllocations;
	std::unordered_map<std::uint32_t, std::vector<std::uint8_t>> m_nonVolatileSettings;
	std::array<std::uint8_t, 16> m_refurbInfo = {};
	std::uint32_t m_fscCachePages = 16;
	std::unordered_map<std::uint32_t, std::uint32_t> m_smbusValues;
	std::unordered_map<std::uint64_t, std::uint8_t> m_pciConfig;
	std::unordered_map<std::uint16_t, std::uint32_t> m_ioPorts;
	std::array<std::uint32_t, 16> m_cryptoOverrides = {};
	bool m_shutdownPending = false;
	bool m_secureTrayEject = false;
	std::uint32_t m_smcScratch = 0;
	std::uint32_t m_profilerAction = 0, m_profilerParameter = 0, m_profilerSamples = 0;
	bool m_irtActive = false;
	mutable std::mutex m_memoryMutex;
	std::uint32_t m_nextHandle = 0x100;
	std::unordered_map<std::uint32_t, ObjectPtr> m_handles;
	std::unordered_map<std::uint32_t, ObjectPtr> m_dispatcherObjects;
	std::unordered_map<std::uint32_t, ObjectPtr> m_guestObjects;
	std::unordered_map<std::wstring, ObjectPtr> m_namedObjects;
	std::unordered_set<std::uint32_t> m_dismountedDevices;
	mutable std::mutex m_objectMutex;
	std::condition_variable m_objectChanged;
	std::atomic<bool> m_stopRequested = false;
	struct ExceptionFrame
	{
		regs_t resume = {};
		std::uint32_t code = 0, registration = 0xFFFFFFFFu, record = 0, context = 0,
			dispatcherContext = 0;
	};
	regs_t m_exceptionResume = {};
	bool m_exceptionPending = false;
	std::uint32_t m_exceptionCode = 0;
	std::uint32_t m_exceptionRegistration = 0xFFFFFFFFu;
	std::uint32_t m_exceptionRecord = 0;
	std::uint32_t m_exceptionContext = 0;
	std::uint32_t m_exceptionDispatcherContext = 0;
	std::vector<ExceptionFrame> m_exceptionFrames;
	regs_t m_unwindResume = {};
	std::uint32_t m_unwindRegistration = 0xFFFFFFFFu;
	std::uint32_t m_unwindTargetFrame = 0;
	std::uint32_t m_unwindTargetIp = 0;
	std::uint32_t m_unwindRecord = 0;
	std::uint32_t m_unwindContext = 0;
	std::uint32_t m_unwindDispatcherContext = 0;
	std::uint32_t m_unwindReturnValue = 0;
	bool m_unwindActive = false;
	bool m_unwindOwnRecord = false;
	std::uint32_t m_currentThread = 0;
	std::uint32_t m_processorControlRegion = 0;
	std::uint32_t m_uniqueProcess = 0;
	struct GuestTlsDirectory
	{
		std::uint32_t start = 0, end = 0, index = 0, callbacks = 0;
		std::uint32_t zeroFill = 0, characteristics = 0;
	} m_tlsDirectory;
	std::vector<std::uint32_t> m_tlsCallbacks;
	std::vector<ThreadContext> m_threads;
	std::size_t m_currentThreadIndex = 0;
	std::uint32_t m_nextThreadId = 1;
	std::vector<DpcItem> m_dpcQueue;
	std::unordered_map<std::uint32_t, InterruptItem> m_interrupts;
	std::vector<std::uint32_t> m_pendingInterrupts;
	std::vector<InterruptFrame> m_interruptFrames;
	std::mutex m_interruptMutex;
	regs_t m_dpcResume = {};
	regs_t m_interruptResume = {};
	regs_t m_synchronizeResume = {};
	regs_t m_threadNotifyResume = {};
	bool m_dpcActive = false;
	bool m_interruptActive = false;
	bool m_synchronizeActive = false;
	bool m_threadNotifyActive = false;
	std::vector<DriverFrame> m_driverFrames;
	std::uint32_t m_activeInterrupt = 0;
	std::uint32_t m_activeInterruptLevel = 0;
	std::uint32_t m_softwareInterrupts = 0;
	std::uint32_t m_enabledInterrupts = 0;
	std::vector<std::uint32_t> m_shutdownRegistrations;
	regs_t m_shutdownResume = {};
	std::size_t m_shutdownRegistrationIndex = 0;
	bool m_shutdownNotificationActive = false;
	bool m_terminateAfterShutdownNotifications = false;
	std::uint32_t m_assertedDeviceSources[28] = {};
	std::uint8_t m_currentIrql = 0;
	std::uint8_t m_savedDpcIrql = 0;
	std::uint8_t m_savedInterruptIrql = 0;
	std::uint8_t m_savedSynchronizeIrql = 0;
	std::vector<std::uint32_t> m_threadNotifyRoutines;
	std::deque<ThreadNotifyItem> m_threadNotifications;
	std::unordered_map<std::uint64_t, std::uint32_t> m_unknownControls;
	bool m_rebootRequested = false;
	std::wstring m_rebootHostPath;
	std::string m_rebootXisoEntry;
	std::array<std::uint8_t, 4096> m_rebootLaunchData = {};
	std::uint64_t m_timesliceCount = 0;
	std::uint64_t m_dispatchCount = 0;
	std::array<bool, 512> m_loggedDispatchOrdinals = {};
	std::uint32_t m_lastDispatchedOrdinal = 0;
	std::uint32_t m_lastDispatchEip = 0;
};
