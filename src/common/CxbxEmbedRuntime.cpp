#include "CxbxEmbedRuntime.h"

#include <atomic>
#include <mutex>

namespace {
std::mutex g_embedMutex;
CxbxEmbedCallbacks g_callbacks{};
CxbxEmbedD3D11Presentation g_d3d11Presentation{};
std::atomic_bool g_active{ false };
std::atomic_bool g_stopRequested{ false };

CxbxEmbedLogLevel ToEmbedLogLevel(LOG_LEVEL level)
{
	return static_cast<CxbxEmbedLogLevel>(level);
}
}

void CxbxEmbedRuntimeActivate(const CxbxEmbedCallbacks& callbacks)
{
	std::scoped_lock lock(g_embedMutex);
	g_callbacks = callbacks;
	g_stopRequested.store(false, std::memory_order_release);
	g_active.store(true, std::memory_order_release);
}

void CxbxEmbedRuntimeDeactivate()
{
	std::scoped_lock lock(g_embedMutex);
	g_callbacks = {};
	g_d3d11Presentation = {};
	g_stopRequested.store(false, std::memory_order_release);
	g_active.store(false, std::memory_order_release);
}

bool CxbxEmbedRuntimeIsActive()
{
	return g_active.load(std::memory_order_acquire);
}

bool CxbxEmbedRuntimeStopRequested()
{
	return g_stopRequested.load(std::memory_order_acquire);
}

void CxbxEmbedRuntimeRequestStop()
{
	g_stopRequested.store(true, std::memory_order_release);
}

void CxbxEmbedRuntimeSetD3D11Presentation(const CxbxEmbedD3D11Presentation& presentation)
{
	std::scoped_lock lock(g_embedMutex);
	g_d3d11Presentation = presentation;
}

const CxbxEmbedD3D11Presentation* CxbxEmbedRuntimeGetD3D11Presentation()
{
	return g_active.load(std::memory_order_acquire) ? &g_d3d11Presentation : nullptr;
}

void CxbxEmbedRuntimeReportLog(CXBXR_MODULE module, LOG_LEVEL level, const char* message)
{
	CxbxEmbedCallbacks callbacks{};
	{
		std::scoped_lock lock(g_embedMutex);
		if (!g_active.load(std::memory_order_acquire) || !g_callbacks.log) {
			return;
		}
		callbacks = g_callbacks;
	}
	callbacks.log(callbacks.user_data, ToEmbedLogLevel(level),
		g_EnumModules2String[to_underlying(module)], message ? message : "");
}

void CxbxEmbedRuntimeReportError(CxbxEmbedResult result, const char* message)
{
	CxbxEmbedCallbacks callbacks{};
	{
		std::scoped_lock lock(g_embedMutex);
		if (!g_active.load(std::memory_order_acquire) || !g_callbacks.error) {
			return;
		}
		callbacks = g_callbacks;
	}
	callbacks.error(callbacks.user_data, result, message ? message : "");
}

CxbxEmbedPromptResult CxbxEmbedRuntimePrompt(
	CxbxEmbedPromptIcon icon, CxbxEmbedPromptButtons buttons,
	CxbxEmbedPromptResult default_result, const char* message)
{
	CxbxEmbedCallbacks callbacks{};
	{
		std::scoped_lock lock(g_embedMutex);
		if (!g_active.load(std::memory_order_acquire) || !g_callbacks.prompt) {
			return default_result;
		}
		callbacks = g_callbacks;
	}
	return callbacks.prompt(callbacks.user_data, icon, buttons, default_result,
		message ? message : "");
}

void CxbxEmbedRuntimeReportHostEvent(CxbxEmbedHostEvent event, uint64_t value)
{
	CxbxEmbedCallbacks callbacks{};
	{
		std::scoped_lock lock(g_embedMutex);
		if (!g_active.load(std::memory_order_acquire) || !g_callbacks.host_event) {
			return;
		}
		callbacks = g_callbacks;
	}
	callbacks.host_event(callbacks.user_data, event, value);
}
