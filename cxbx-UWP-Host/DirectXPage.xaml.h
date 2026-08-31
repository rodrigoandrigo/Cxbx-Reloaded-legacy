#pragma once

#include "DirectXPage.g.h"
#include "Common\DeviceResources.h"
#include "cxbx_UWP_HostMain.h"

namespace cxbx_UWP_Host
{
	public ref class DirectXPage sealed
	{
	public:
		DirectXPage();
		virtual ~DirectXPage();

		void SaveInternalState(Windows::Foundation::Collections::IPropertySet^ state);
		void LoadInternalState(Windows::Foundation::Collections::IPropertySet^ state);
		Windows::Foundation::IAsyncAction^ SuspendAsync();

	private:
		void OnVisibilityChanged(Windows::UI::Core::CoreWindow^ sender,
			Windows::UI::Core::VisibilityChangedEventArgs^ args);
		void OnDpiChanged(Windows::Graphics::Display::DisplayInformation^ sender, Platform::Object^ args);
		void OnOrientationChanged(Windows::Graphics::Display::DisplayInformation^ sender, Platform::Object^ args);
		void OnDisplayContentsInvalidated(Windows::Graphics::Display::DisplayInformation^ sender, Platform::Object^ args);
		void OnCompositionScaleChanged(Windows::UI::Xaml::Controls::SwapChainPanel^ sender, Platform::Object^ args);
		void OnSwapChainPanelSizeChanged(Platform::Object^ sender, Windows::UI::Xaml::SizeChangedEventArgs^ args);

		void SelectTitle_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ args);
		void Start_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ args);
		void Stop_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ args);
		void RestoreLastTitle();
		void SelectTitle(Windows::Storage::StorageFile^ file);
		void AppendLog(const std::wstring& message, bool error);
		void UpdateButtons();

		std::shared_ptr<DX::DeviceResources> m_deviceResources;
		std::unique_ptr<cxbx_UWP_HostMain> m_main;
		Windows::Storage::StorageFile^ m_selectedTitle;
		bool m_windowVisible = true;
	};
}
