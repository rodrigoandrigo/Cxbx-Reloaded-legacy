#include "pch.h"
#include "Cxbx_R_uwpMain.h"
#include "..\..\src\core\hle\D3D8\Rendering\UwpD3D11Host.h"

using namespace Cxbx_R_uwp;
using namespace Concurrency;

Cxbx_R_uwpMain::Cxbx_R_uwpMain(const std::shared_ptr<DX::DeviceResources>& deviceResources) :
	m_deviceResources(deviceResources), m_surfaceReady(false), m_tracking(false),
	m_hasPresentedGuestFrame(false)
{
	m_deviceResources->RegisterDeviceNotify(this);
	RegisterSurface();
}

Cxbx_R_uwpMain::~Cxbx_R_uwpMain()
{
	CxbxUwpResetD3D11Surface();
	m_deviceResources->RegisterDeviceNotify(nullptr);
}

void Cxbx_R_uwpMain::RegisterSurface()
{
	auto output = m_deviceResources->GetOutputSize();
	CxbxUwpD3D11Surface surface = {};
	surface.device = m_deviceResources->GetD3DDevice();
	surface.context = m_deviceResources->GetD3DDeviceContext();
	surface.swapChain = m_deviceResources->GetSwapChain();
	surface.width = static_cast<UINT>(output.Width);
	surface.height = static_cast<UINT>(output.Height);
	surface.dpi = m_deviceResources->GetDpi();
	m_surfaceReady = SUCCEEDED(CxbxUwpRegisterD3D11Surface(&surface));
}

void Cxbx_R_uwpMain::DrawIdleFrame()
{
	if (!m_surfaceReady) return;
	auto context = m_deviceResources->GetD3DDeviceContext();
	const HRESULT guestFrame = CxbxUwpRenderSubmittedFrame();
	if (guestFrame == S_FALSE) {
		// A guest flip is normally slower than the XAML composition callback.
		// Presenting an untouched alternate swap-chain buffer here replaces the
		// last valid guest image with the startup clear colour. Keep the displayed
		// buffer until NV2A submits another completed surface.
		if (m_hasPresentedGuestFrame) return;
		ID3D11RenderTargetView* target = m_deviceResources->GetBackBufferRenderTargetView();
		const float background[] = { 0.018f, 0.027f, 0.047f, 1.0f };
		context->OMSetRenderTargets(1, &target, nullptr);
		context->ClearRenderTargetView(target, background);
	}
	else if (SUCCEEDED(guestFrame)) {
		m_hasPresentedGuestFrame = true;
	}
	m_deviceResources->Present();
	CxbxUwpNotifyD3D11Present(guestFrame == S_FALSE ? S_OK : guestFrame);
}

void Cxbx_R_uwpMain::RenderFrame()
{
	critical_section::scoped_lock lock(m_criticalSection);
	DrawIdleFrame();
}

void Cxbx_R_uwpMain::CreateWindowSizeDependentResources()
{
	RegisterSurface();
	DrawIdleFrame();
}

void Cxbx_R_uwpMain::StartRenderLoop()
{
	critical_section::scoped_lock lock(m_criticalSection);
	DrawIdleFrame();
}

void Cxbx_R_uwpMain::StopRenderLoop()
{
	// Backend_D3D11 owns the frame loop after boot; no template worker exists.
}

void Cxbx_R_uwpMain::OnDeviceLost()
{
	CxbxUwpResetD3D11Surface();
	m_surfaceReady = false;
	m_hasPresentedGuestFrame = false;
}

void Cxbx_R_uwpMain::OnDeviceRestored()
{
	RegisterSurface();
	DrawIdleFrame();
}
