#include "CxbxEmbed.h"

#include <atomic>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>

#include "common/CxbxEmbedRuntime.h"
#include "common/CxbxEmbedStorage.h"
#include "common/ReserveAddressRanges.h"
#include "common/cxbxr.hpp"
#include "common/util/cliConfig.hpp"
#include "common/win32/EmuShared.h"
#include "core/kernel/init/CxbxKrnl.h"
#include "devices/x86/CxbxCpuBackendLoader.h"

void KeSignalVBlankPending();

struct CxbxEmbedInstance {
	std::mutex mutex;
	std::thread worker;
	CxbxEmbedConfig config{};
	CxbxEmbedCallbacks callbacks{};
	std::string titlePath;
	std::string localDataPath;
	std::string cachePath;
	std::string cpuBackendModule;
	std::string titleRelativePath;
	std::atomic<CxbxEmbedState> state{ CXBX_EMBED_STATE_CREATED };
};

namespace {
std::atomic_bool g_embedInstanceExists{ false };

bool IsCompatible(const CxbxEmbedConfig* config, const CxbxEmbedCallbacks* callbacks)
{
	return config && callbacks && config->struct_size >= sizeof(CxbxEmbedConfig) &&
		callbacks->struct_size >= sizeof(CxbxEmbedCallbacks) &&
		config->abi_version == CXBX_EMBED_ABI_VERSION &&
		callbacks->abi_version == CXBX_EMBED_CALLBACKS_VERSION &&
		((config->title_path_utf8 && config->title_path_utf8[0] != '\0') ||
			CxbxEmbedHasBrokeredTitle(config->brokered_storage));
}

bool HasD3D11Presentation(const CxbxEmbedD3D11Presentation& presentation)
{
	return presentation.struct_size >= sizeof(CxbxEmbedD3D11Presentation) &&
		presentation.abi_version == CXBX_EMBED_D3D11_PRESENTATION_VERSION &&
		presentation.d3d11_device && presentation.d3d11_context &&
		presentation.render_target && presentation.width && presentation.height && presentation.present;
}

void SetState(CxbxEmbedInstance* instance, CxbxEmbedState state)
{
	instance->state.store(state, std::memory_order_release);
	if (instance->callbacks.state_changed) {
		instance->callbacks.state_changed(instance->callbacks.user_data, state);
	}
}

void ReportFailure(CxbxEmbedInstance* instance, CxbxEmbedResult result, const char* message)
{
	CxbxEmbedRuntimeReportError(result, message);
	SetState(instance, CXBX_EMBED_STATE_FAILED);
}

void JoinFinishedWorker(CxbxEmbedInstance* instance)
{
	if (instance->worker.joinable()) {
		instance->worker.join();
	}
}

void InitializeWorker(CxbxEmbedInstance* instance)
{
	// All UI, storage and D3D resources remain owned by the UWP host. The
	// core's potentially long-running bootstrap begins only after Launch().
	if (CxbxEmbedRuntimeStopRequested()) {
		SetState(instance, CXBX_EMBED_STATE_STOPPED);
		return;
	}
	SetState(instance, CXBX_EMBED_STATE_READY);
}

void LaunchWorker(CxbxEmbedInstance* instance)
{
	unsigned int reservedSystems = SYSTEM_ALL;
	blocks_reserved_t blocksReserved{};

	try {
		std::string title_path = instance->titlePath;
		if (title_path.empty()) {
			std::string storage_error;
			const std::string cache_path = instance->cachePath.empty() ? instance->localDataPath : instance->cachePath;
			if (!CxbxEmbedMaterializeBrokeredTitle(instance->config.brokered_storage, cache_path, title_path, storage_error)) {
				ReportFailure(instance, CXBX_EMBED_LAUNCH_FAILED, storage_error.c_str());
				return;
			}
		}

		if (!AttemptReserveAddressRanges(&reservedSystems, blocksReserved)) {
			char message[192]{};
			std::snprintf(message, sizeof(message),
				"Unable to reserve Xbox address range 0x%08X (size 0x%08X, Win32 error %lu).",
				GetLastAddressReservationBase(), GetLastAddressReservationSize(),
				GetLastAddressReservationError());
			ReportFailure(instance, CXBX_EMBED_LAUNCH_FAILED, message);
			return;
		}
		CxbxCpuBackendConfigure(instance->cpuBackendModule.empty() ? nullptr :
			instance->cpuBackendModule.c_str());

		// The legacy core still obtains boot options from cli_config. Supplying
		// them directly avoids GetCommandLine and lets the host own activation.
		cli_config::SetLoad(title_path);
		if (!EmuShared::Init(cli_config::GetSessionID())) {
			ReportFailure(instance, CXBX_EMBED_INITIALIZATION_FAILED, "Could not initialize Cxbx shared state.");
			return;
		}
		if (!instance->localDataPath.empty()) {
			g_EmuShared->SetDataLocation(instance->localDataPath.c_str());
		}
		if (!HandleFirstLaunch()) {
			EmuShared::Cleanup();
			ReportFailure(instance, CXBX_EMBED_INITIALIZATION_FAILED, "Cxbx initialization was rejected.");
			return;
		}

		CxbxKrnlEmulate(reservedSystems, blocksReserved);
		EmuShared::Cleanup();
		SetState(instance, CxbxEmbedRuntimeStopRequested() ? CXBX_EMBED_STATE_STOPPED : CXBX_EMBED_STATE_FAILED);
	}
	catch (const CxbxEmbeddedAbort& error) {
		CxbxrShutDown();
		ReportFailure(instance, CXBX_EMBED_LAUNCH_FAILED, error.what());
	}
}
}

extern "C" CxbxEmbedResult CXBX_EMBED_CALL CxbxEmbed_Create(
	const CxbxEmbedConfig* config, const CxbxEmbedCallbacks* callbacks, CxbxEmbedInstance** instance)
{
	if (!instance || !IsCompatible(config, callbacks)) {
		return CXBX_EMBED_INVALID_ARGUMENT;
	}
	bool expected = false;
	if (!g_embedInstanceExists.compare_exchange_strong(expected, true)) {
		return CXBX_EMBED_BUSY;
	}

	auto* created = new CxbxEmbedInstance();
	created->config = *config;
	created->callbacks = *callbacks;
	// A brokered StorageFile intentionally has no process-visible path. Do not
	// pass its null path through std::string::operator=(const char*); the title
	// is materialized by LaunchWorker through the storage callbacks instead.
	created->titlePath = config->title_path_utf8 ? config->title_path_utf8 : "";
	created->localDataPath = config->local_data_path_utf8 ? config->local_data_path_utf8 : "";
	created->cachePath = config->cache_path_utf8 ? config->cache_path_utf8 : "";
	created->cpuBackendModule = config->cpu_backend_module_utf8 ?
		config->cpu_backend_module_utf8 : "qemu-cxbx-i386.dll";
	created->config.cpu_backend_module_utf8 = created->cpuBackendModule.c_str();
	created->titleRelativePath = config->brokered_storage.title_relative_path_utf8 ?
		config->brokered_storage.title_relative_path_utf8 : "";
	created->config.brokered_storage.title_relative_path_utf8 = created->titleRelativePath.empty() ?
		nullptr : created->titleRelativePath.c_str();
#if defined(CXBXR_UWP)
	if (!HasD3D11Presentation(created->config.d3d11_presentation)) {
		delete created;
		g_embedInstanceExists.store(false, std::memory_order_release);
		return CXBX_EMBED_INVALID_ARGUMENT;
	}
#endif
	CxbxEmbedRuntimeActivate(created->callbacks);
	CxbxEmbedRuntimeSetD3D11Presentation(created->config.d3d11_presentation);
	*instance = created;
	return CXBX_EMBED_OK;
}

extern "C" CxbxEmbedResult CXBX_EMBED_CALL CxbxEmbed_InitializeAsync(CxbxEmbedInstance* instance)
{
	if (!instance) {
		return CXBX_EMBED_INVALID_ARGUMENT;
	}
	std::scoped_lock lock(instance->mutex);
	if (instance->state.load() != CXBX_EMBED_STATE_CREATED) {
		return CXBX_EMBED_INVALID_STATE;
	}
	SetState(instance, CXBX_EMBED_STATE_INITIALIZING);
	instance->worker = std::thread(InitializeWorker, instance);
	return CXBX_EMBED_OK;
}

extern "C" CxbxEmbedResult CXBX_EMBED_CALL CxbxEmbed_Launch(CxbxEmbedInstance* instance)
{
	if (!instance) {
		return CXBX_EMBED_INVALID_ARGUMENT;
	}
	std::scoped_lock lock(instance->mutex);
	if (instance->state.load() != CXBX_EMBED_STATE_READY) {
		return CXBX_EMBED_INVALID_STATE;
	}
	JoinFinishedWorker(instance);
	SetState(instance, CXBX_EMBED_STATE_RUNNING);
	instance->worker = std::thread(LaunchWorker, instance);
	return CXBX_EMBED_OK;
}

extern "C" CxbxEmbedResult CXBX_EMBED_CALL CxbxEmbed_RequestStop(CxbxEmbedInstance* instance)
{
	if (!instance) {
		return CXBX_EMBED_INVALID_ARGUMENT;
	}
	const auto state = instance->state.load();
	if (state != CXBX_EMBED_STATE_INITIALIZING && state != CXBX_EMBED_STATE_READY && state != CXBX_EMBED_STATE_RUNNING) {
		return CXBX_EMBED_INVALID_STATE;
	}
	SetState(instance, CXBX_EMBED_STATE_STOPPING);
	CxbxEmbedRuntimeRequestStop();
	if (state == CXBX_EMBED_STATE_READY) {
		JoinFinishedWorker(instance);
		SetState(instance, CXBX_EMBED_STATE_STOPPED);
		return CXBX_EMBED_OK;
	}
	// The DPC loop owns the core's blocking wait. Wake it so it observes the
	// stop flag instead of requiring a frame or guest interrupt.
	KeSignalVBlankPending();
	return CXBX_EMBED_OK;
}

extern "C" CxbxEmbedState CXBX_EMBED_CALL CxbxEmbed_GetState(const CxbxEmbedInstance* instance)
{
	return instance ? instance->state.load(std::memory_order_acquire) : CXBX_EMBED_STATE_FAILED;
}

extern "C" void CXBX_EMBED_CALL CxbxEmbed_Destroy(CxbxEmbedInstance* instance)
{
	if (!instance) {
		return;
	}
	const auto state = instance->state.load();
	if (state == CXBX_EMBED_STATE_INITIALIZING || state == CXBX_EMBED_STATE_READY || state == CXBX_EMBED_STATE_RUNNING) {
		(void)CxbxEmbed_RequestStop(instance);
	}
	JoinFinishedWorker(instance);
	CxbxCpuBackendShutdown();
	CxbxEmbedRuntimeDeactivate();
	g_embedInstanceExists.store(false, std::memory_order_release);
	delete instance;
}
