#include "pch.h"
#include "DirectXPage.xaml.h"
#include "UwpStorageBroker.h"
#include "..\..\src\core\kernel\init\UwpDeviceBus.h"
#include "..\..\src\core\hle\D3D8\Rendering\UwpD3D11Host.h"

#include <algorithm>
#include <cmath>

using namespace Cxbx_R_uwp;
using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::Graphics::Display;
using namespace Windows::Gaming::Input;
using namespace Windows::Storage;
using namespace Windows::Storage::Pickers;
using namespace Windows::UI::Core;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Media;
using namespace concurrency;

namespace
{
	String^ SettingKey(const wchar_t* name) { return ref new String(name); }

	IPropertyValue^ ReadProperty(IPropertySet^ values, const wchar_t* name)
	{
		auto key = SettingKey(name);
		return values && values->HasKey(key) ? dynamic_cast<IPropertyValue^>(values->Lookup(key)) : nullptr;
	}

	bool ReadBool(IPropertySet^ values, const wchar_t* name, bool fallback)
	{
		auto value = ReadProperty(values, name);
		return value && value->Type == PropertyType::Boolean ? value->GetBoolean() : fallback;
	}

	int ReadInt(IPropertySet^ values, const wchar_t* name, int fallback)
	{
		auto value = ReadProperty(values, name);
		return value && value->Type == PropertyType::Int32 ? value->GetInt32() : fallback;
	}

	double ReadDouble(IPropertySet^ values, const wchar_t* name, double fallback)
	{
		auto value = ReadProperty(values, name);
		return value && value->Type == PropertyType::Double ? value->GetDouble() : fallback;
	}

	bool IsChecked(CheckBox^ checkBox)
	{
		return checkBox && checkBox->IsChecked && checkBox->IsChecked->Value;
	}

	double ApplyDeadzone(double value, double deadzone)
	{
		const double magnitude = std::abs(value);
		if (magnitude <= deadzone) return 0.0;
		const double normalized = (magnitude - deadzone) / (1.0 - deadzone);
		return value < 0.0 ? -normalized : normalized;
	}
}

DirectXPage::DirectXPage() : m_windowVisible(true), m_selectedGame(nullptr)
{
	InitializeComponent();
	auto window = Window::Current->CoreWindow;
	window->VisibilityChanged += ref new TypedEventHandler<CoreWindow^, VisibilityChangedEventArgs^>(this, &DirectXPage::OnVisibilityChanged);
	window->KeyDown += ref new TypedEventHandler<CoreWindow^, KeyEventArgs^>(this, &DirectXPage::OnKeyDown);
	auto display = DisplayInformation::GetForCurrentView();
	display->DpiChanged += ref new TypedEventHandler<DisplayInformation^, Object^>(this, &DirectXPage::OnDpiChanged);
	display->OrientationChanged += ref new TypedEventHandler<DisplayInformation^, Object^>(this, &DirectXPage::OnOrientationChanged);
	DisplayInformation::DisplayContentsInvalidated += ref new TypedEventHandler<DisplayInformation^, Object^>(this, &DirectXPage::OnDisplayContentsInvalidated);
	swapChainPanel->CompositionScaleChanged += ref new TypedEventHandler<SwapChainPanel^, Object^>(this, &DirectXPage::OnCompositionScaleChanged);
	swapChainPanel->SizeChanged += ref new SizeChangedEventHandler(this, &DirectXPage::OnSwapChainPanelSizeChanged);

	m_deviceResources = std::make_shared<DX::DeviceResources>();
	m_deviceResources->SetSwapChainPanel(swapChainPanel);
	m_main.reset(new Cxbx_R_uwpMain(m_deviceResources));
	m_session.reset(new CxbxUwpEmulatorSession());
	m_audioHost.reset(new CxbxUwpAudioHost());
	LoadAppSettings();
	ApplyAppSettings();
	m_renderingToken = CompositionTarget::Rendering += ref new EventHandler<Object^>(this, &DirectXPage::OnRendering);
	m_main->StartRenderLoop();
	statusText->Text = m_main->IsSurfaceReady()
		? "D3D11 pronto. Selecione um XBE, ISO ou pasta autorizada."
		: "Falha ao registrar a superfície D3D11.";
}

DirectXPage::~DirectXPage()
{
	CompositionTarget::Rendering -= m_renderingToken;
	SetGamePresentationMode(false);
	if (m_session) m_session->Stop();
	if (m_main) m_main->StopRenderLoop();
}

void DirectXPage::OnRendering(Object^, Object^)
{
	for (unsigned port = 0; port < 4; ++port) {
		CxbxUwpGamepadState state = {};
		const unsigned assignment = m_portAssignments[port];
		const unsigned physicalIndex = assignment ? assignment - 1 : 0;
		if (assignment && physicalIndex < Gamepad::Gamepads->Size && (m_windowVisible || !m_ignoreInputWhenUnfocused)) {
			auto reading = Gamepad::Gamepads->GetAt(physicalIndex)->GetCurrentReading();
		auto pressed = [reading](GamepadButtons button) -> bool {
			const auto mask = static_cast<unsigned>(button);
			return (static_cast<unsigned>(reading.Buttons) & mask) == mask;
		};
		state.packet = ++m_gamepadPacket;
		state.buttons = static_cast<std::uint16_t>(
			(pressed(GamepadButtons::DPadUp) ? 0x0001 : 0) |
			(pressed(GamepadButtons::DPadDown) ? 0x0002 : 0) |
			(pressed(GamepadButtons::DPadLeft) ? 0x0004 : 0) |
			(pressed(GamepadButtons::DPadRight) ? 0x0008 : 0) |
			(pressed(GamepadButtons::Menu) ? 0x0010 : 0) |
			(pressed(GamepadButtons::View) ? 0x0020 : 0) |
			(pressed(GamepadButtons::LeftThumbstick) ? 0x0040 : 0) |
			(pressed(GamepadButtons::RightThumbstick) ? 0x0080 : 0));
		auto analog = [](double value) { return static_cast<std::uint8_t>((std::max)(0.0, (std::min)(1.0, value)) * 255.0); };
		auto axis = [this](double value) { value = ApplyDeadzone(value, m_gamepadDeadzone); return static_cast<std::int16_t>((std::max)(-1.0, (std::min)(1.0, value)) * 32767.0); };
		state.analog[0] = pressed(GamepadButtons::A) ? 255 : 0;
		state.analog[1] = pressed(GamepadButtons::B) ? 255 : 0;
		state.analog[2] = pressed(GamepadButtons::X) ? 255 : 0;
		state.analog[3] = pressed(GamepadButtons::Y) ? 255 : 0;
		state.analog[4] = pressed(GamepadButtons::RightShoulder) ? 255 : 0;
		state.analog[5] = pressed(GamepadButtons::LeftShoulder) ? 255 : 0;
		state.analog[6] = analog(reading.LeftTrigger);
		state.analog[7] = analog(reading.RightTrigger);
		state.leftX = axis(reading.LeftThumbstickX); state.leftY = axis(reading.LeftThumbstickY);
		state.rightX = axis(reading.RightThumbstickX); state.rightY = axis(reading.RightThumbstickY);
		}
		CxbxUwpSetGamepadState(port, &state);
	}
	if (m_windowVisible && IsChecked(fpsOverlayCheck)) {
		const auto now = GetTickCount64();
		if (!m_overlayWindowStart) m_overlayWindowStart = now;
		++m_overlayFrameCount;
		const auto elapsed = now - m_overlayWindowStart;
		if (elapsed >= 500) {
			wchar_t text[48] = {};
			swprintf_s(text, L"FPS: %.1f", m_overlayFrameCount * 1000.0 / elapsed);
			overlayFpsText->Text = ref new String(text);
			m_overlayFrameCount = 0; m_overlayWindowStart = now;
		}
	}
	if (m_windowVisible && m_main) m_main->RenderFrame();
}

void DirectXPage::SaveInternalState(IPropertySet^)
{
	SaveAppSettings();
	Concurrency::critical_section::scoped_lock lock(m_main->GetCriticalSection());
	m_main->StopRenderLoop();
	m_deviceResources->Trim();
}

void DirectXPage::LoadInternalState(IPropertySet^) { m_main->StartRenderLoop(); }

void DirectXPage::OnVisibilityChanged(CoreWindow^, VisibilityChangedEventArgs^ args)
{
	m_windowVisible = args->Visible;
	if (m_audioHost && m_muteWhenUnfocused) m_audioHost->SetMuted(!m_windowVisible);
	if (m_windowVisible) m_main->StartRenderLoop(); else m_main->StopRenderLoop();
}

void DirectXPage::OnDpiChanged(DisplayInformation^ sender, Object^)
{
	Concurrency::critical_section::scoped_lock lock(m_main->GetCriticalSection());
	m_deviceResources->SetDpi(sender->LogicalDpi);
	m_main->CreateWindowSizeDependentResources();
}

void DirectXPage::OnOrientationChanged(DisplayInformation^ sender, Object^)
{
	Concurrency::critical_section::scoped_lock lock(m_main->GetCriticalSection());
	m_deviceResources->SetCurrentOrientation(sender->CurrentOrientation);
	m_main->CreateWindowSizeDependentResources();
}

void DirectXPage::OnDisplayContentsInvalidated(DisplayInformation^, Object^) { m_deviceResources->ValidateDevice(); }

void DirectXPage::OnCompositionScaleChanged(SwapChainPanel^ sender, Object^)
{
	Concurrency::critical_section::scoped_lock lock(m_main->GetCriticalSection());
	m_deviceResources->SetCompositionScale(sender->CompositionScaleX, sender->CompositionScaleY);
	m_main->CreateWindowSizeDependentResources();
}

void DirectXPage::OnSwapChainPanelSizeChanged(Object^, SizeChangedEventArgs^ args)
{
	Concurrency::critical_section::scoped_lock lock(m_main->GetCriticalSection());
	m_deviceResources->SetLogicalSize(args->NewSize);
	m_main->CreateWindowSizeDependentResources();
}

void DirectXPage::SetGamePresentationMode(bool enabled)
{
	if (enabled == m_gamePresentationMode) return;
	if (enabled) {
		chromeGrid->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
	} else {
		chromeGrid->Visibility = Windows::UI::Xaml::Visibility::Visible;
	}
	m_gamePresentationMode = enabled;
}

void DirectXPage::OnKeyDown(CoreWindow^, KeyEventArgs^ args)
{
	if (m_gamePresentationMode && args->VirtualKey == Windows::System::VirtualKey::Escape) {
		SetGamePresentationMode(false);
		args->Handled = true;
	}
}

void DirectXPage::OpenGameFolder_Click(Object^, RoutedEventArgs^)
{
	auto picker = ref new FolderPicker();
	picker->SuggestedStartLocation = PickerLocationId::ComputerFolder;
	picker->FileTypeFilter->Append("*");
	create_task(picker->PickSingleFolderAsync()).then([this](StorageFolder^ folder) {
		if (!folder) return task_from_result<String^>(nullptr);
		return create_task(UwpStorageBroker::SetGameFolderAsync(folder));
	}).then([this](String^ path) {
		if (path) { m_selectedGame = path; selectedGameText->Text = path; startButton->IsEnabled = true; statusText->Text = "default.xbe será executado diretamente na pasta autorizada."; }
	}).then([this](task<void> result) { try { result.get(); } catch (Exception^ e) { statusText->Text = e->Message; } });
}

void DirectXPage::OpenGameFile_Click(Object^, RoutedEventArgs^)
{
	auto picker = ref new FileOpenPicker();
	picker->SuggestedStartLocation = PickerLocationId::ComputerFolder;
	picker->FileTypeFilter->Append(".xbe");
	picker->FileTypeFilter->Append(".iso");
	picker->FileTypeFilter->Append(".xiso");
	create_task(picker->PickSingleFileAsync()).then([this](StorageFile^ file) {
		if (!file) return task_from_result<String^>(nullptr);
		statusText->Text = "Autorizando o XBE/XISO no local original…";
		return create_task(UwpStorageBroker::SetGameFileAsync(file));
	}).then([this](String^ path) {
		if (path) { m_selectedGame = path; selectedGameText->Text = path; startButton->IsEnabled = true; statusText->Text = "Jogo autorizado no local original, sem cópia."; }
	}).then([this](task<void> result) { try { result.get(); } catch (Exception^ e) { statusText->Text = e->Message; } });
}

void DirectXPage::StartButton_Click(Object^, RoutedEventArgs^)
{
	SaveAppSettings();
	ApplyAppSettings();
	if (!m_selectedGame || !UwpStorageBroker::DataRoot || !UwpStorageBroker::LogPath || !UwpStorageBroker::GameRoot) {
		statusText->Text = "O armazenamento brokered ainda não foi inicializado.";
		return;
	}
	std::wstring game(m_selectedGame->Data());
	std::wstring data(UwpStorageBroker::DataRoot->Data());
	std::wstring log(UwpStorageBroker::LogPath->Data());
	std::wstring gameRoot(UwpStorageBroker::GameRoot->Data());
	std::uint32_t flags = 0;
	if (IsChecked(ignoreSignatureCheck)) flags |= CxbxUwpIgnoreInvalidXbeSignature;
	if (IsChecked(ignoreSecurityCheck)) flags |= CxbxUwpIgnoreInvalidXbeSecurity;
	if (IsChecked(useAllCoresCheck)) flags |= CxbxUwpUseAllCores;
	if (IsChecked(skipRdtscCheck)) flags |= CxbxUwpSkipRdtscPatching;
	if (IsChecked(disablePixelShadersCheck)) flags |= CxbxUwpDisablePixelShaders;
	const auto consoleType = static_cast<std::uint32_t>((std::max)(0, consoleTypeCombo->SelectedIndex));
	startButton->IsEnabled = false;
	statusText->Text = "Iniciando sessão no processo UWP…";
	create_task([this, game, data, log, gameRoot, flags, consoleType]() {
		CxbxUwpBootConfig config = { sizeof(CxbxUwpBootConfig), game.c_str(), data.c_str(), log.c_str(), gameRoot.c_str(),
			consoleType, flags };
		return m_session->Start(config);
	}).then([this](HRESULT result) {
		if (SUCCEEDED(result)) {
			statusText->Text = "Emulação em execução.";
			pauseButton->IsEnabled = true;
			stopButton->IsEnabled = true;
			SetGamePresentationMode(true);
		} else if (result == HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)) {
			statusText->Text = "Sessão in-process pronta, mas falta registrar um backend CPU Xbox x86-em-x64.";
			startButton->IsEnabled = true;
		} else {
			if (IsChecked(popupCheck)) {
				wchar_t message[80] = {};
				swprintf_s(message, L"Falha ao iniciar a sessão. HRESULT 0x%08X", static_cast<unsigned>(result));
				statusText->Text = ref new String(message);
			} else statusText->Text = "Não foi possível iniciar a emulação; consulte a aba Log.";
			startButton->IsEnabled = true;
		}
	}, task_continuation_context::use_current());
}

void DirectXPage::PauseButton_Click(Object^, RoutedEventArgs^)
{
	HRESULT result = m_session->State() == CxbxUwpSessionState::Paused ? m_session->Resume() : m_session->Pause();
	if (SUCCEEDED(result)) {
		SetGamePresentationMode(false);
		bool paused = m_session->State() == CxbxUwpSessionState::Paused;
		pauseButton->Content = paused ? "Retomar" : "Pausar";
		statusText->Text = paused ? "Emulação pausada." : "Emulação retomada.";
	}
}

void DirectXPage::StopButton_Click(Object^, RoutedEventArgs^)
{
	HRESULT result = m_session->Stop();
	if (SUCCEEDED(result)) {
		pauseButton->IsEnabled = false;
		stopButton->IsEnabled = false;
		startButton->IsEnabled = m_selectedGame != nullptr;
		statusText->Text = "Emulação encerrada.";
	}
}

void DirectXPage::SetDefaultSettings()
{
	renderScaleCombo->SelectedIndex = 0;
	vsyncCheck->IsChecked = true;
	aspectCheck->IsChecked = true;
	linearFilteringCheck->IsChecked = true;
	volumeSlider->Value = 100.0;
	muteUnfocusedCheck->IsChecked = true;
	pcmCodecCheck->IsChecked = true;
	xadpcmCodecCheck->IsChecked = true;
	unknownCodecCheck->IsChecked = true;
	port1Combo->SelectedIndex = 1;
	port2Combo->SelectedIndex = 0;
	port3Combo->SelectedIndex = 0;
	port4Combo->SelectedIndex = 0;
	deadzoneSlider->Value = 12.0;
	ignoreUnfocusedInputCheck->IsChecked = true;
	networkModeCombo->SelectedIndex = 1;
	consoleTypeCombo->SelectedIndex = 0;
	ignoreSignatureCheck->IsChecked = false;
	ignoreSecurityCheck->IsChecked = false;
	useAllCoresCheck->IsChecked = true;
	skipRdtscCheck->IsChecked = false;
	disablePixelShadersCheck->IsChecked = false;
	popupCheck->IsChecked = true;
	fpsOverlayCheck->IsChecked = false;
	buildOverlayCheck->IsChecked = false;
	statsOverlayCheck->IsChecked = false;
	titleOverlayCheck->IsChecked = false;
	fileOverlayCheck->IsChecked = false;
}

void DirectXPage::LoadAppSettings()
{
	SetDefaultSettings();
	auto values = ApplicationData::Current->LocalSettings->Values;
	renderScaleCombo->SelectedIndex = (std::max)(0, (std::min)(11, ReadInt(values, L"Video.RenderScale", 0)));
	vsyncCheck->IsChecked = ReadBool(values, L"Video.VSync", true);
	aspectCheck->IsChecked = ReadBool(values, L"Video.MaintainAspect", true);
	linearFilteringCheck->IsChecked = ReadBool(values, L"Video.LinearFiltering", true);
	volumeSlider->Value = (std::max)(0.0, (std::min)(100.0, ReadDouble(values, L"Audio.Volume", 100.0)));
	muteUnfocusedCheck->IsChecked = ReadBool(values, L"Audio.MuteWhenUnfocused", true);
	pcmCodecCheck->IsChecked = ReadBool(values, L"Audio.CodecPcm", true);
	xadpcmCodecCheck->IsChecked = ReadBool(values, L"Audio.CodecXadpcm", true);
	unknownCodecCheck->IsChecked = ReadBool(values, L"Audio.CodecUnknown", true);
	ComboBox^ ports[] = { port1Combo, port2Combo, port3Combo, port4Combo };
	const wchar_t* portKeys[] = { L"Input.Port1", L"Input.Port2", L"Input.Port3", L"Input.Port4" };
	for (unsigned port = 0; port < 4; ++port) ports[port]->SelectedIndex = (std::max)(0, (std::min)(4, ReadInt(values, portKeys[port], port == 0 ? 1 : 0)));
	deadzoneSlider->Value = (std::max)(0.0, (std::min)(40.0, ReadDouble(values, L"Input.Deadzone", 12.0)));
	ignoreUnfocusedInputCheck->IsChecked = ReadBool(values, L"Input.IgnoreWhenUnfocused", true);
	networkModeCombo->SelectedIndex = (std::max)(0, (std::min)(1, ReadInt(values, L"Network.Mode", 1)));
	consoleTypeCombo->SelectedIndex = (std::max)(0, (std::min)(3, ReadInt(values, L"System.ConsoleType", 0)));
	ignoreSignatureCheck->IsChecked = ReadBool(values, L"System.IgnoreXbeSignature", false);
	ignoreSecurityCheck->IsChecked = ReadBool(values, L"System.IgnoreXbeSecurity", false);
	useAllCoresCheck->IsChecked = ReadBool(values, L"Hacks.UseAllCores", true);
	skipRdtscCheck->IsChecked = ReadBool(values, L"Hacks.SkipRdtscPatching", false);
	disablePixelShadersCheck->IsChecked = ReadBool(values, L"Hacks.DisablePixelShaders", false);
	popupCheck->IsChecked = ReadBool(values, L"Debug.StatusErrors", true);
	fpsOverlayCheck->IsChecked = ReadBool(values, L"Overlay.Fps", false);
	buildOverlayCheck->IsChecked = ReadBool(values, L"Overlay.Build", false);
	statsOverlayCheck->IsChecked = ReadBool(values, L"Overlay.Stats", false);
	titleOverlayCheck->IsChecked = ReadBool(values, L"Overlay.Title", false);
	fileOverlayCheck->IsChecked = ReadBool(values, L"Overlay.File", false);
}

void DirectXPage::SaveAppSettings()
{
	auto values = ApplicationData::Current->LocalSettings->Values;
	auto putBool = [values](const wchar_t* key, bool value) { values->Insert(SettingKey(key), PropertyValue::CreateBoolean(value)); };
	auto putInt = [values](const wchar_t* key, int value) { values->Insert(SettingKey(key), PropertyValue::CreateInt32(value)); };
	auto putDouble = [values](const wchar_t* key, double value) { values->Insert(SettingKey(key), PropertyValue::CreateDouble(value)); };
	putInt(L"Video.RenderScale", renderScaleCombo->SelectedIndex);
	putBool(L"Video.VSync", IsChecked(vsyncCheck));
	putBool(L"Video.MaintainAspect", IsChecked(aspectCheck));
	putBool(L"Video.LinearFiltering", IsChecked(linearFilteringCheck));
	putDouble(L"Audio.Volume", volumeSlider->Value);
	putBool(L"Audio.MuteWhenUnfocused", IsChecked(muteUnfocusedCheck));
	putBool(L"Audio.CodecPcm", IsChecked(pcmCodecCheck));
	putBool(L"Audio.CodecXadpcm", IsChecked(xadpcmCodecCheck));
	putBool(L"Audio.CodecUnknown", IsChecked(unknownCodecCheck));
	putInt(L"Input.Port1", port1Combo->SelectedIndex); putInt(L"Input.Port2", port2Combo->SelectedIndex);
	putInt(L"Input.Port3", port3Combo->SelectedIndex); putInt(L"Input.Port4", port4Combo->SelectedIndex);
	putDouble(L"Input.Deadzone", deadzoneSlider->Value);
	putBool(L"Input.IgnoreWhenUnfocused", IsChecked(ignoreUnfocusedInputCheck));
	putInt(L"Network.Mode", networkModeCombo->SelectedIndex);
	putInt(L"System.ConsoleType", consoleTypeCombo->SelectedIndex);
	putBool(L"System.IgnoreXbeSignature", IsChecked(ignoreSignatureCheck));
	putBool(L"System.IgnoreXbeSecurity", IsChecked(ignoreSecurityCheck));
	putBool(L"Hacks.UseAllCores", IsChecked(useAllCoresCheck));
	putBool(L"Hacks.SkipRdtscPatching", IsChecked(skipRdtscCheck));
	putBool(L"Hacks.DisablePixelShaders", IsChecked(disablePixelShadersCheck));
	putBool(L"Debug.StatusErrors", IsChecked(popupCheck));
	putBool(L"Overlay.Fps", IsChecked(fpsOverlayCheck));
	putBool(L"Overlay.Build", IsChecked(buildOverlayCheck));
	putBool(L"Overlay.Stats", IsChecked(statsOverlayCheck));
	putBool(L"Overlay.Title", IsChecked(titleOverlayCheck));
	putBool(L"Overlay.File", IsChecked(fileOverlayCheck));
}

void DirectXPage::ApplyAppSettings()
{
	CxbxUwpD3D11Settings video = { IsChecked(vsyncCheck), IsChecked(aspectCheck),
		IsChecked(linearFilteringCheck), static_cast<unsigned>(renderScaleCombo->SelectedIndex + 1) };
	CxbxUwpSetD3D11Settings(&video);
	if (m_audioHost) {
		m_audioHost->SetVolume(static_cast<float>(volumeSlider->Value / 100.0));
		m_muteWhenUnfocused = IsChecked(muteUnfocusedCheck);
		m_audioHost->SetMuted(m_muteWhenUnfocused && !m_windowVisible);
	}
	m_portAssignments[0] = static_cast<unsigned>((std::max)(0, port1Combo->SelectedIndex));
	m_portAssignments[1] = static_cast<unsigned>((std::max)(0, port2Combo->SelectedIndex));
	m_portAssignments[2] = static_cast<unsigned>((std::max)(0, port3Combo->SelectedIndex));
	m_portAssignments[3] = static_cast<unsigned>((std::max)(0, port4Combo->SelectedIndex));
	m_gamepadDeadzone = deadzoneSlider->Value / 100.0;
	m_ignoreInputWhenUnfocused = IsChecked(ignoreUnfocusedInputCheck);
	CxbxUwpDeviceSettings devices = { IsChecked(pcmCodecCheck), IsChecked(xadpcmCodecCheck),
		IsChecked(unknownCodecCheck), networkModeCombo->SelectedIndex != 0,
		static_cast<std::uint32_t>((std::max)(0, consoleTypeCombo->SelectedIndex)) };
	CxbxUwpSetDeviceSettings(&devices);
	overlayFpsText->Visibility = IsChecked(fpsOverlayCheck) ? Windows::UI::Xaml::Visibility::Visible : Windows::UI::Xaml::Visibility::Collapsed;
	overlayBuildText->Visibility = IsChecked(buildOverlayCheck) ? Windows::UI::Xaml::Visibility::Visible : Windows::UI::Xaml::Visibility::Collapsed;
	overlayStatsText->Visibility = IsChecked(statsOverlayCheck) ? Windows::UI::Xaml::Visibility::Visible : Windows::UI::Xaml::Visibility::Collapsed;
	overlayTitleText->Visibility = IsChecked(titleOverlayCheck) ? Windows::UI::Xaml::Visibility::Visible : Windows::UI::Xaml::Visibility::Collapsed;
	overlayFileText->Visibility = IsChecked(fileOverlayCheck) ? Windows::UI::Xaml::Visibility::Visible : Windows::UI::Xaml::Visibility::Collapsed;
	const bool showOverlay = IsChecked(fpsOverlayCheck) || IsChecked(buildOverlayCheck) ||
		IsChecked(statsOverlayCheck) || IsChecked(titleOverlayCheck) || IsChecked(fileOverlayCheck);
	emulationOverlay->Visibility = showOverlay ? Windows::UI::Xaml::Visibility::Visible : Windows::UI::Xaml::Visibility::Collapsed;
	std::wstring selected = m_selectedGame ? m_selectedGame->Data() : L"Nenhum título selecionado";
	const auto separator = selected.find_last_of(L"\\/");
	overlayTitleText->Text = ref new String((separator == std::wstring::npos ? selected : selected.substr(separator + 1)).c_str());
	overlayFileText->Text = ref new String(selected.c_str());
}

void DirectXPage::SaveSettingsButton_Click(Object^, RoutedEventArgs^)
{
	SaveAppSettings();
	ApplyAppSettings();
	statusText->Text = "Vídeo, áudio e entrada aplicados; opções do núcleo valerão no próximo boot.";
}

void DirectXPage::ResetSettingsButton_Click(Object^, RoutedEventArgs^)
{
	SetDefaultSettings();
	SaveAppSettings();
	ApplyAppSettings();
	statusText->Text = "Padrões restaurados; opções do núcleo valerão no próximo boot.";
}

void DirectXPage::SettingsButton_Click(Object^, RoutedEventArgs^)
{
	mainPivot->SelectedIndex = 0;
}

void DirectXPage::RefreshLog_Click(Object^, RoutedEventArgs^)
{
	create_task(ApplicationData::Current->LocalFolder->CreateFolderAsync("CxbxR", CreationCollisionOption::OpenIfExists))
		.then([](StorageFolder^ folder) { return create_task(folder->CreateFileAsync("CxbxR.log", CreationCollisionOption::OpenIfExists)); })
		.then([](StorageFile^ file) { return create_task(FileIO::ReadTextAsync(file)); })
		.then([this](String^ text) { logText->Text = text->IsEmpty() ? "O log ainda está vazio." : text; })
		.then([this](task<void> result) { try { result.get(); } catch (Exception^ e) { logText->Text = e->Message; } });
}
