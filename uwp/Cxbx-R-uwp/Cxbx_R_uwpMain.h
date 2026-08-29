#pragma once

#include "Common\DeviceResources.h"

// Owns the native D3D11 hand-off to the emulation core. The core renders and
// presents its own frames; this host does not run the DirectX template scene.
namespace Cxbx_R_uwp
{
	class Cxbx_R_uwpMain : public DX::IDeviceNotify
	{
	public:
		explicit Cxbx_R_uwpMain(const std::shared_ptr<DX::DeviceResources>& deviceResources);
		~Cxbx_R_uwpMain();
		void CreateWindowSizeDependentResources();
		void StartTracking() { m_tracking = true; }
		void TrackingUpdate(float) {}
		void StopTracking() { m_tracking = false; }
		bool IsTracking() const { return m_tracking; }
		void StartRenderLoop();
		void StopRenderLoop();
		void RenderFrame();
		bool IsSurfaceReady() const { return m_surfaceReady; }
		Concurrency::critical_section& GetCriticalSection() { return m_criticalSection; }
		virtual void OnDeviceLost();
		virtual void OnDeviceRestored();

	private:
		void RegisterSurface();
		void DrawIdleFrame();
		std::shared_ptr<DX::DeviceResources> m_deviceResources;
		Concurrency::critical_section m_criticalSection;
		bool m_surfaceReady;
		bool m_tracking;
		bool m_hasPresentedGuestFrame;
	};
}
