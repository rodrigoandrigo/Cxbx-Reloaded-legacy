// UWP replacement for HostWindow.cpp. Keyboard, pointer, cursor and window
// events belong to the host application's CoreWindow/SwapChainPanel.
#include <windows.h>
#include <functional>
#include <cstdio>

#include "../RenderGlobals.h"

const char* D3DErrorString(HRESULT hResult)
{
	static thread_local char buffer[1024];
	if (const char* description = CxbxGetErrorDescription(hResult)) {
		snprintf(buffer, sizeof(buffer), "0x%08lX: %s",
			static_cast<unsigned long>(hResult), description);
	} else {
		snprintf(buffer, sizeof(buffer), "0x%08lX: Unknown D3D error.",
			static_cast<unsigned long>(hResult));
	}
	return buffer;
}

void RunOnWndMsgThread(const std::function<void()>& func)
{
	// The embedding host calls into the core from its render worker. There is
	// no private HWND message thread to marshal to.
	func();
}

void CxbxInitWindow()
{
	// Dimensions and presentation state come from CxbxEmbedD3D11Presentation.
}

void DrawUEM(HWND)
{
	// The host owns visual error reporting in UWP.
}

void CxbxClipCursor(HWND)
{
}

void CxbxReleaseCursor()
{
}

void CxbxUpdateCursor(bool)
{
}
