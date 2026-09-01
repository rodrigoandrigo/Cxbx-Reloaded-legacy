// Stable C ABI for UWP and other in-process Cxbx hosts.
//
// Keep this header free of C++, WinRT and Cxbx-internal types.  A host owns
// its UI thread, storage objects and D3D objects; the core only receives data
// that is explicitly represented by this ABI.
#pragma once

#include <stdint.h>

#if defined(_WIN32)
# if defined(CXBXR_EMU_EXPORTS)
#  define CXBX_EMBED_API __declspec(dllexport)
# else
#  define CXBX_EMBED_API __declspec(dllimport)
# endif
# define CXBX_EMBED_CALL __cdecl
#else
# define CXBX_EMBED_API
# define CXBX_EMBED_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CXBX_EMBED_ABI_VERSION 4u
#define CXBX_EMBED_CALLBACKS_VERSION 2u
#define CXBX_EMBED_CONFIG_VERSION 4u
#define CXBX_EMBED_STORAGE_VERSION 1u

// Brokered handles are host-owned opaque values, never WinRT pointers or
// Win32 HANDLEs. A UWP host may back one with StorageFile, StorageFolder or
// an IRandomAccessStream; the DLL may use it only through the callbacks below.
typedef uint64_t CxbxEmbedStorageHandle;
#define CXBX_EMBED_INVALID_STORAGE_HANDLE UINT64_C(0)

typedef struct CxbxEmbedInstance CxbxEmbedInstance;

typedef enum CxbxEmbedResult {
	CXBX_EMBED_OK = 0,
	CXBX_EMBED_INVALID_ARGUMENT,
	CXBX_EMBED_INVALID_STATE,
	CXBX_EMBED_BUSY,
	CXBX_EMBED_INITIALIZATION_FAILED,
	CXBX_EMBED_LAUNCH_FAILED,
	CXBX_EMBED_STOPPED,
} CxbxEmbedResult;

typedef enum CxbxEmbedState {
	CXBX_EMBED_STATE_CREATED = 0,
	CXBX_EMBED_STATE_INITIALIZING,
	CXBX_EMBED_STATE_READY,
	CXBX_EMBED_STATE_RUNNING,
	CXBX_EMBED_STATE_STOPPING,
	CXBX_EMBED_STATE_STOPPED,
	CXBX_EMBED_STATE_FAILED,
} CxbxEmbedState;

typedef enum CxbxEmbedLogLevel {
	CXBX_EMBED_LOG_DEBUG = 0,
	CXBX_EMBED_LOG_INFO,
	CXBX_EMBED_LOG_WARNING,
	CXBX_EMBED_LOG_ERROR,
	CXBX_EMBED_LOG_FATAL,
} CxbxEmbedLogLevel;

typedef enum CxbxEmbedPromptIcon {
	CXBX_EMBED_PROMPT_ICON_UNKNOWN = 0,
	CXBX_EMBED_PROMPT_ICON_QUESTION,
	CXBX_EMBED_PROMPT_ICON_INFO,
	CXBX_EMBED_PROMPT_ICON_WARNING,
	CXBX_EMBED_PROMPT_ICON_ERROR,
} CxbxEmbedPromptIcon;

typedef enum CxbxEmbedPromptButtons {
	CXBX_EMBED_PROMPT_BUTTONS_UNKNOWN = 0,
	CXBX_EMBED_PROMPT_BUTTONS_OK,
	CXBX_EMBED_PROMPT_BUTTONS_OK_CANCEL,
	CXBX_EMBED_PROMPT_BUTTONS_ABORT_RETRY_IGNORE,
	CXBX_EMBED_PROMPT_BUTTONS_YES_NO_CANCEL,
	CXBX_EMBED_PROMPT_BUTTONS_YES_NO,
	CXBX_EMBED_PROMPT_BUTTONS_RETRY_CANCEL,
} CxbxEmbedPromptButtons;

typedef enum CxbxEmbedPromptResult {
	CXBX_EMBED_PROMPT_UNKNOWN = 0,
	CXBX_EMBED_PROMPT_OK,
	CXBX_EMBED_PROMPT_CANCEL,
	CXBX_EMBED_PROMPT_ABORT,
	CXBX_EMBED_PROMPT_RETRY,
	CXBX_EMBED_PROMPT_IGNORE,
	CXBX_EMBED_PROMPT_YES,
	CXBX_EMBED_PROMPT_NO,
} CxbxEmbedPromptResult;

typedef enum CxbxEmbedHostEvent {
	CXBX_EMBED_HOST_EVENT_LLE_FLAGS = 0,
	CXBX_EMBED_HOST_EVENT_XBOX_LED_COLOUR,
	CXBX_EMBED_HOST_EVENT_LOG_ENABLED,
	CXBX_EMBED_HOST_EVENT_KERNEL_READY,
	CXBX_EMBED_HOST_EVENT_OVERLAY,
	CXBX_EMBED_HOST_EVENT_WINDOW_HANDLE,
	CXBX_EMBED_HOST_EVENT_WINDOW_DESTROYED,
} CxbxEmbedHostEvent;

typedef enum CxbxEmbedStorageResult {
	CXBX_EMBED_STORAGE_OK = 0,
	CXBX_EMBED_STORAGE_ACCESS_DENIED,
	CXBX_EMBED_STORAGE_NOT_FOUND,
	CXBX_EMBED_STORAGE_IO_ERROR,
	CXBX_EMBED_STORAGE_INVALID_HANDLE,
	CXBX_EMBED_STORAGE_NOT_SUPPORTED,
} CxbxEmbedStorageResult;

typedef enum CxbxEmbedStorageAccess {
	CXBX_EMBED_STORAGE_READ = 1u << 0,
	CXBX_EMBED_STORAGE_WRITE = 1u << 1,
} CxbxEmbedStorageAccess;

typedef void (CXBX_EMBED_CALL *CxbxEmbedLogCallback)(
	void* user_data, CxbxEmbedLogLevel level, const char* module_utf8, const char* message_utf8);
typedef void (CXBX_EMBED_CALL *CxbxEmbedErrorCallback)(
	void* user_data, CxbxEmbedResult result, const char* message_utf8);
typedef void (CXBX_EMBED_CALL *CxbxEmbedStateCallback)(
	void* user_data, CxbxEmbedState state);
// Called on the emulator worker. The UWP host marshals UI work to its
// dispatcher, waits for the user's choice, and returns it to the core.
typedef CxbxEmbedPromptResult (CXBX_EMBED_CALL *CxbxEmbedPromptCallback)(
	void* user_data, CxbxEmbedPromptIcon icon, CxbxEmbedPromptButtons buttons,
	CxbxEmbedPromptResult default_result, const char* message_utf8);
typedef void (CXBX_EMBED_CALL *CxbxEmbedHostEventCallback)(
	void* user_data, CxbxEmbedHostEvent event, uint64_t value);

// The host owns the UWP swap chain and presents this texture after the core
// calls present. The three D3D pointers are ABI-opaque ID3D11Device,
// ID3D11DeviceContext and ID3D11Texture2D objects on the same device.
typedef void (CXBX_EMBED_CALL *CxbxEmbedPresentCallback)(
	void* user_data, void* render_target, uint32_t width, uint32_t height);

typedef struct CxbxEmbedD3D11Presentation {
	uint32_t struct_size;
	uint32_t abi_version;
	void* user_data;
	void* d3d11_device;
	void* d3d11_context;
	void* render_target;
	uint32_t width;
	uint32_t height;
	CxbxEmbedPresentCallback present;
} CxbxEmbedD3D11Presentation;

#define CXBX_EMBED_D3D11_PRESENTATION_VERSION 1u

// All callbacks run on the emulator worker, never on the UWP UI thread.
// The host must keep the represented StorageFile/StorageFolder/stream alive
// until CxbxEmbed_Destroy returns.
typedef CxbxEmbedStorageResult (CXBX_EMBED_CALL *CxbxEmbedStorageGetSizeCallback)(
	void* user_data, CxbxEmbedStorageHandle file, uint64_t* size_out);
typedef CxbxEmbedStorageResult (CXBX_EMBED_CALL *CxbxEmbedStorageReadAtCallback)(
	void* user_data, CxbxEmbedStorageHandle file, uint64_t offset,
	void* buffer, uint32_t bytes_requested, uint32_t* bytes_read_out);
typedef CxbxEmbedStorageResult (CXBX_EMBED_CALL *CxbxEmbedStorageOpenRelativeCallback)(
	void* user_data, CxbxEmbedStorageHandle folder, const char* relative_path_utf8,
	uint32_t access, CxbxEmbedStorageHandle* file_out);
typedef void (CXBX_EMBED_CALL *CxbxEmbedStorageCloseCallback)(
	void* user_data, CxbxEmbedStorageHandle file);

typedef struct CxbxEmbedCallbacks {
	uint32_t struct_size;
	uint32_t abi_version;
	void* user_data;
	CxbxEmbedLogCallback log;
	CxbxEmbedErrorCallback error;
	CxbxEmbedStateCallback state_changed;
	CxbxEmbedPromptCallback prompt;
	CxbxEmbedHostEventCallback host_event;
} CxbxEmbedCallbacks;

typedef struct CxbxEmbedBrokeredStorage {
	uint32_t struct_size;
	uint32_t abi_version;
	void* user_data;
	// A StorageFile selected by FileOpenPicker (or restored by
	// FutureAccessList). It is materialized into the app's cache before the
	// legacy XBE loader runs.
	CxbxEmbedStorageHandle title_file;
	// Optional StorageFolder capability. It is accessed only through
	// open_relative, never converted to a desktop path.
	CxbxEmbedStorageHandle content_folder;
	// UTF-8 path of the XBE below content_folder. Used when title_file is not
	// supplied, allowing a FolderPicker result to launch a title.
	const char* title_relative_path_utf8;
	CxbxEmbedStorageGetSizeCallback get_size;
	CxbxEmbedStorageReadAtCallback read_at;
	CxbxEmbedStorageOpenRelativeCallback open_relative;
	CxbxEmbedStorageCloseCallback close;
} CxbxEmbedBrokeredStorage;

typedef struct CxbxEmbedConfig {
	uint32_t struct_size;
	uint32_t abi_version;
	// UTF-8 paths owned by the host. In UWP, these must be derived from
	// ApplicationData folders. title_path_utf8 is a desktop compatibility
	// fallback; prefer brokered_storage.title_file for UWP/Xbox.
	const char* title_path_utf8;
	const char* local_data_path_utf8;
	const char* cache_path_utf8;
	// Packaged QEMU/TCG CPU backend. When null or empty, the core uses
	// "qemu-cxbx-i386.dll". This is a module name, not a brokered file path.
	const char* cpu_backend_module_utf8;
	// Required by CXBXR_UWP_CORE. The core AddRefs the D3D interfaces while it
	// runs, but the host retains ownership of its swap chain and UI thread.
	CxbxEmbedD3D11Presentation d3d11_presentation;
	CxbxEmbedBrokeredStorage brokered_storage;
} CxbxEmbedConfig;

#if defined(__cplusplus) && defined(_WIN64)
static_assert(sizeof(void*) == 8, "The UWP embedding ABI requires an x64 host");
static_assert(sizeof(CxbxEmbedStorageHandle) == 8, "Brokered handles are always 64-bit");
static_assert(sizeof(CxbxEmbedD3D11Presentation) == 56, "Unexpected x64 D3D ABI packing");
static_assert(sizeof(CxbxEmbedCallbacks) == 56, "Unexpected x64 callback ABI packing");
static_assert(sizeof(CxbxEmbedBrokeredStorage) == 72, "Unexpected x64 storage ABI packing");
static_assert(sizeof(CxbxEmbedConfig) == 168, "Unexpected x64 configuration ABI packing");
#endif

CXBX_EMBED_API CxbxEmbedResult CXBX_EMBED_CALL CxbxEmbed_Create(
	const CxbxEmbedConfig* config, const CxbxEmbedCallbacks* callbacks, CxbxEmbedInstance** instance);
CXBX_EMBED_API CxbxEmbedResult CXBX_EMBED_CALL CxbxEmbed_InitializeAsync(CxbxEmbedInstance* instance);
CXBX_EMBED_API CxbxEmbedResult CXBX_EMBED_CALL CxbxEmbed_Launch(CxbxEmbedInstance* instance);
CXBX_EMBED_API CxbxEmbedResult CXBX_EMBED_CALL CxbxEmbed_RequestStop(CxbxEmbedInstance* instance);
CXBX_EMBED_API CxbxEmbedState CXBX_EMBED_CALL CxbxEmbed_GetState(const CxbxEmbedInstance* instance);
CXBX_EMBED_API void CXBX_EMBED_CALL CxbxEmbed_Destroy(CxbxEmbedInstance* instance);

#ifdef __cplusplus
}
#endif
