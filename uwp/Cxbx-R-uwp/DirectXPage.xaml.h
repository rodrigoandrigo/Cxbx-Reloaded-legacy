#pragma once

#include "DirectXPage.g.h"
#include "Common\DeviceResources.h"
#include "Cxbx_R_uwpMain.h"
#include "UwpAudioHost.h"
#include "..\..\src\core\kernel\init\UwpEmulatorSession.h"

namespace Cxbx_R_uwp
{
	public ref class DirectXPage sealed
	{
	public:
		DirectXPage();
		virtual ~DirectXPage();
		void SaveInternalState(Windows::Foundation::Collections::IPropertySet^ state);
		void LoadInternalState(Windows::Foundation::Collections::IPropertySet^ state);

	private:
		void OnVisibilityChanged(Windows::UI::Core::CoreWindow^ sender, Windows::UI::Core::VisibilityChangedEventArgs^ args);
		void OnDpiChanged(Windows::Graphics::Display::DisplayInformation^ sender, Platform::Object^ args);
		void OnOrientationChanged(Windows::Graphics::Display::DisplayInformation^ sender, Platform::Object^ args);
		void OnDisplayContentsInvalidated(Windows::Graphics::Display::DisplayInformation^ sender, Platform::Object^ args);
		void OnCompositionScaleChanged(Windows::UI::Xaml::Controls::SwapChainPanel^ sender, Platform::Object^ args);
		void OnSwapChainPanelSizeChanged(Platform::Object^ sender, Windows::UI::Xaml::SizeChangedEventArgs^ args);
		void OnRendering(Platform::Object^ sender, Platform::Object^ args);
		void OnKeyDown(Windows::UI::Core::CoreWindow^ sender, Windows::UI::Core::KeyEventArgs^ args);
		void SetGamePresentationMode(bool enabled);
		void OpenGameFolder_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ args);
		void OpenGameFile_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ args);
		void StartButton_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ args);
		void PauseButton_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ args);
		void StopButton_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ args);
		void SettingsButton_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ args);
		void SaveSettingsButton_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ args);
		void ResetSettingsButton_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ args);
		void RefreshLog_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ args);
		void LoadAppSettings();
		void SaveAppSettings();
		void ApplyAppSettings();
		void SetDefaultSettings();

		std::shared_ptr<DX::DeviceResources> m_deviceResources;
		std::unique_ptr<Cxbx_R_uwpMain> m_main;
		std::unique_ptr<CxbxUwpEmulatorSession> m_session;
		std::unique_ptr<CxbxUwpAudioHost> m_audioHost;
		std::uint32_t m_gamepadPacket = 0;
		std::uint32_t m_overlayFrameCount = 0;
		std::uint64_t m_overlayWindowStart = 0;
		unsigned m_portAssignments[4] = { 1, 0, 0, 0 };
		double m_gamepadDeadzone = 0.12;
		bool m_ignoreInputWhenUnfocused = true;
		bool m_muteWhenUnfocused = true;
		bool m_windowVisible;
		bool m_gamePresentationMode = false;
		Windows::Foundation::EventRegistrationToken m_renderingToken;
		Platform::String^ m_selectedGame;
	};
}
