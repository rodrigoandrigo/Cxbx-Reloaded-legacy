#define LOG_PREFIX CXBXR_MODULE::X86

#include "devices/x86/CxbxCpuBackendLoader.h"

#include <mutex>
#include <windows.h>

#include "Logging.h"

namespace {
std::mutex g_backendMutex;
std::string g_backendName = "qemu-cxbx-i386.dll";
HMODULE g_backendModule = nullptr;
CxbxCpuBackendExports g_backend{};

std::wstring Utf8ToWide(const std::string& text)
{
	if (text.empty()) {
		return {};
	}
	const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
		text.c_str(), -1, nullptr, 0);
	if (length <= 0) {
		return {};
	}
	std::wstring wide(static_cast<size_t>(length), L'\0');
	if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), -1,
		wide.data(), length)) {
		return {};
	}
	wide.resize(static_cast<size_t>(length - 1));
	return wide;
}

template<typename T>
bool Resolve(T& target, const char* name, std::string& error)
{
	target = reinterpret_cast<T>(GetProcAddress(g_backendModule, name));
	if (target) {
		return true;
	}
	error = std::string("CPU backend is missing required export: ") + name;
	return false;
}

void ClearBackend()
{
	g_backend = {};
	if (g_backendModule) {
		FreeLibrary(g_backendModule);
		g_backendModule = nullptr;
	}
}
}

void CxbxCpuBackendConfigure(const char* module_name_utf8)
{
	std::scoped_lock lock(g_backendMutex);
	if (g_backendModule) {
		return;
	}
	g_backendName = module_name_utf8 && module_name_utf8[0]
		? module_name_utf8 : "qemu-cxbx-i386.dll";
}

bool CxbxCpuBackendInitialize(std::string& error)
{
	std::scoped_lock lock(g_backendMutex);
	if (g_backendModule) {
		return true;
	}

	const std::wstring moduleName = Utf8ToWide(g_backendName);
	if (moduleName.empty()) {
		error = "CPU backend DLL name is not valid UTF-8.";
		return false;
	}
#if defined(CXBXR_UWP)
	g_backendModule = LoadPackagedLibrary(moduleName.c_str(), 0);
#else
	g_backendModule = LoadLibraryW(moduleName.c_str());
#endif
	if (!g_backendModule) {
		error = "Unable to load CPU backend '" + g_backendName +
			"' (Win32 error " + std::to_string(GetLastError()) + ").";
		return false;
	}

	if (!Resolve(g_backend.get_api_version, "qemu_cxbx_cpu_get_api_version", error) ||
		!Resolve(g_backend.create, "qemu_cxbx_cpu_create", error) ||
		!Resolve(g_backend.destroy, "qemu_cxbx_cpu_destroy", error) ||
		!Resolve(g_backend.map_memory, "qemu_cxbx_cpu_map_memory", error) ||
		!Resolve(g_backend.unmap_memory, "qemu_cxbx_cpu_unmap_memory", error) ||
		!Resolve(g_backend.guest_commit, "qemu_cxbx_cpu_guest_commit", error) ||
		!Resolve(g_backend.guest_protect, "qemu_cxbx_cpu_guest_protect", error) ||
		!Resolve(g_backend.guest_decommit, "qemu_cxbx_cpu_guest_decommit", error) ||
		!Resolve(g_backend.set_registers, "qemu_cxbx_cpu_set_registers", error) ||
		!Resolve(g_backend.get_registers, "qemu_cxbx_cpu_get_registers", error) ||
		!Resolve(g_backend.run, "qemu_cxbx_cpu_run", error) ||
		!Resolve(g_backend.interrupt, "qemu_cxbx_cpu_interrupt", error) ||
		!Resolve(g_backend.request_stop, "qemu_cxbx_cpu_request_stop", error) ||
		!Resolve(g_backend.flush, "qemu_cxbx_cpu_flush", error)) {
		ClearBackend();
		return false;
	}

	const uint32_t version = g_backend.get_api_version();
	if (QEMU_CXBX_CPU_ABI_MAJOR(version) !=
		QEMU_CXBX_CPU_ABI_MAJOR(QEMU_CXBX_CPU_ABI_VERSION)) {
		error = "CPU backend ABI major version is incompatible.";
		ClearBackend();
		return false;
	}

	EmuLog(LOG_LEVEL::INFO, "Loaded CPU backend %s (ABI %u.%u)",
		g_backendName.c_str(), version >> 16, version & 0xffffu);
	return true;
}

void CxbxCpuBackendShutdown()
{
	std::scoped_lock lock(g_backendMutex);
	ClearBackend();
}

bool CxbxCpuBackendIsLoaded()
{
	std::scoped_lock lock(g_backendMutex);
	return g_backendModule != nullptr;
}

const CxbxCpuBackendExports* CxbxCpuBackendGetExports()
{
	return g_backendModule ? &g_backend : nullptr;
}
