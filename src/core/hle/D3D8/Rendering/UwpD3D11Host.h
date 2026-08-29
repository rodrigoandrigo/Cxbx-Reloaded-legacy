#pragma once

#include <d3d11.h>
#include <dxgi1_2.h>

// Native contract between the XAML UWP host and Backend_D3D11.  It contains
// no C++/CX types, so the emulation core never crosses the UWP ABI boundary.
struct CxbxUwpD3D11Surface
{
	ID3D11Device* device;
	ID3D11DeviceContext* context;
	IDXGISwapChain1* swapChain;
	UINT width;
	UINT height;
	float dpi;
};

// Native guest-frame contract. The producer supplies a completed Xbox colour
// buffer; ownership remains with the producer only until Submit returns.
// BGRA8 is the native little-endian X8R8G8B8/A8R8G8B8 representation used by
// the Xbox. RGBA8 and RGB565 are accepted for diagnostic/minimal backends.
enum class CxbxUwpGuestPixelFormat : unsigned
{
	Bgra8,
	Rgba8,
	Rgb565,
};

struct CxbxUwpD3D11Settings
{
	bool verticalSync;
	bool maintainAspectRatio;
	bool linearFiltering;
	unsigned renderScale;
};

void CxbxUwpSetD3D11Settings(const CxbxUwpD3D11Settings* settings);
CxbxUwpD3D11Settings CxbxUwpGetD3D11Settings();

// Register replaces the current surface and retains every COM interface.
// Acquire returns a retained snapshot; Release balances that snapshot.
HRESULT CxbxUwpRegisterD3D11Surface(const CxbxUwpD3D11Surface* surface);
HRESULT CxbxUwpAcquireD3D11Surface(CxbxUwpD3D11Surface* surface);
void CxbxUwpReleaseD3D11Surface(CxbxUwpD3D11Surface* surface);
void CxbxUwpResetD3D11Surface();

// Copies a completed guest framebuffer into the UWP presentation queue. It is
// safe to call on the x86 executor thread; the XAML render thread performs the
// D3D11 upload and presentation. Frames are deliberately coalesced so a fast
// guest never blocks the UI thread.
HRESULT CxbxUwpSubmitGuestFrame(const void* pixels, UINT width, UINT height,
	UINT pitch, CxbxUwpGuestPixelFormat format = CxbxUwpGuestPixelFormat::Bgra8);

// Renders the most recently submitted framebuffer, scaled to the swap-chain
// dimensions. S_FALSE means that no guest frame is queued.
HRESULT CxbxUwpRenderSubmittedFrame();

// Must be called only after a real swap-chain presentation completes. It
// produces the Xbox GPU/VBlank edge (PCI IRQ 3) for a connected miniport ISR.
void CxbxUwpNotifyD3D11Present(HRESULT presentationResult);
