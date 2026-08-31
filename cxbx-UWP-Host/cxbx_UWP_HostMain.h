#pragma once

#include "Common\DeviceResources.h"
#include "..\src\emulator\CxbxEmbed.h"

#include <atomic>
#include <functional>
#include <fstream>
#include <map>
#include <mutex>
#include <string>

namespace cxbx_UWP_Host
{
	class cxbx_UWP_HostMain final : public DX::IDeviceNotify
	{
	public:
		using UiCallback = std::function<void(const std::wstring&, bool)>;

		explicit cxbx_UWP_HostMain(const std::shared_ptr<DX::DeviceResources>& deviceResources);
		~cxbx_UWP_HostMain();

		void SetUiCallback(UiCallback callback);
		Concurrency::task<bool> StartAsync(Windows::Storage::StorageFile^ titleFile);
		Concurrency::task<void> StopAsync();
		bool IsRunning() const;
		bool CanResize() const;
		std::wstring StatusText() const;
		Concurrency::critical_section& GetCriticalSection() { return m_criticalSection; }

		void OnDeviceLost() override;
		void OnDeviceRestored() override;

	private:
		struct StorageEntry
		{
			Windows::Storage::StorageFile^ file = nullptr;
			Windows::Storage::StorageFolder^ folder = nullptr;
			bool closeable = false;
		};

		using CreateFn = decltype(&CxbxEmbed_Create);
		using InitializeFn = decltype(&CxbxEmbed_InitializeAsync);
		using LaunchFn = decltype(&CxbxEmbed_Launch);
		using RequestStopFn = decltype(&CxbxEmbed_RequestStop);
		using GetStateFn = decltype(&CxbxEmbed_GetState);
		using DestroyFn = decltype(&CxbxEmbed_Destroy);

		bool LoadCore(std::wstring& error);
		void UnloadCore();
		bool CreateAndLaunch(Windows::Storage::StorageFile^ titleFile, std::wstring& error);
		void StopAndDestroy();
		void Notify(const std::wstring& message, bool error = false);
		void SetStatus(const std::wstring& status, bool error = false);
		void AppendLogLine(const std::wstring& line);
		CxbxEmbedStorageHandle RegisterFile(Windows::Storage::StorageFile^ file, bool closeable);
		CxbxEmbedStorageHandle RegisterFolder(Windows::Storage::StorageFolder^ folder, bool closeable);
		StorageEntry FindStorage(CxbxEmbedStorageHandle handle) const;

		static void CXBX_EMBED_CALL LogCallback(void* userData, CxbxEmbedLogLevel level,
			const char* moduleUtf8, const char* messageUtf8);
		static void CXBX_EMBED_CALL ErrorCallback(void* userData, CxbxEmbedResult result,
			const char* messageUtf8);
		static void CXBX_EMBED_CALL StateCallback(void* userData, CxbxEmbedState state);
		static CxbxEmbedPromptResult CXBX_EMBED_CALL PromptCallback(void* userData,
			CxbxEmbedPromptIcon icon, CxbxEmbedPromptButtons buttons,
			CxbxEmbedPromptResult defaultResult, const char* messageUtf8);
		static void CXBX_EMBED_CALL HostEventCallback(void* userData,
			CxbxEmbedHostEvent event, uint64_t value);
		static void CXBX_EMBED_CALL PresentCallback(void* userData, void* renderTarget,
			uint32_t width, uint32_t height);
		static CxbxEmbedStorageResult CXBX_EMBED_CALL StorageGetSize(void* userData,
			CxbxEmbedStorageHandle file, uint64_t* sizeOut);
		static CxbxEmbedStorageResult CXBX_EMBED_CALL StorageReadAt(void* userData,
			CxbxEmbedStorageHandle file, uint64_t offset, void* buffer,
			uint32_t bytesRequested, uint32_t* bytesReadOut);
		static CxbxEmbedStorageResult CXBX_EMBED_CALL StorageOpenRelative(void* userData,
			CxbxEmbedStorageHandle folder, const char* relativePathUtf8,
			uint32_t access, CxbxEmbedStorageHandle* fileOut);
		static void CXBX_EMBED_CALL StorageClose(void* userData, CxbxEmbedStorageHandle file);

		CxbxEmbedPromptResult ShowPrompt(CxbxEmbedPromptButtons buttons,
			CxbxEmbedPromptResult defaultResult, const std::wstring& message);

		std::shared_ptr<DX::DeviceResources> m_deviceResources;
		Windows::UI::Core::CoreDispatcher^ m_dispatcher;
		Concurrency::critical_section m_criticalSection;
		mutable std::mutex m_mutex;
		mutable std::mutex m_lifecycleMutex;
		mutable std::mutex m_storageMutex;
		mutable std::mutex m_logMutex;
		UiCallback m_uiCallback;
		std::map<CxbxEmbedStorageHandle, StorageEntry> m_storage;
		CxbxEmbedStorageHandle m_nextStorageHandle = 1;
		CxbxEmbedStorageHandle m_titleHandle = CXBX_EMBED_INVALID_STORAGE_HANDLE;
		std::ofstream m_logFile;
		std::wstring m_status;
		std::string m_localDataPath;
		std::string m_cachePath;
		std::atomic_bool m_stopping{ false };

		HMODULE m_module = nullptr;
		CxbxEmbedInstance* m_instance = nullptr;
		CreateFn m_create = nullptr;
		InitializeFn m_initialize = nullptr;
		LaunchFn m_launch = nullptr;
		RequestStopFn m_requestStop = nullptr;
		GetStateFn m_getState = nullptr;
		DestroyFn m_destroy = nullptr;
	};
}
