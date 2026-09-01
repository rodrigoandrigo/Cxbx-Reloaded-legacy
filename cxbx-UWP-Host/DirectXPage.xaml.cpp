#include "pch.h"
#include "DirectXPage.xaml.h"

#include <ppltasks.h>

using namespace cxbx_UWP_Host;
using namespace Concurrency;
using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::Graphics::Display;
using namespace Windows::Storage;
using namespace Windows::Storage::AccessCache;
using namespace Windows::Storage::Pickers;
using namespace Windows::UI::Core;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;

namespace
{
	constexpr wchar_t LastTitleToken[] = L"cxbx-last-title";
}

DirectXPage::DirectXPage()
{
	InitializeComponent();

	auto window = Window::Current->CoreWindow;
	window->VisibilityChanged += ref new TypedEventHandler<CoreWindow^, VisibilityChangedEventArgs^>(
		this, &DirectXPage::OnVisibilityChanged);
	auto display = DisplayInformation::GetForCurrentView();
	display->DpiChanged += ref new TypedEventHandler<DisplayInformation^, Object^>(
		this, &DirectXPage::OnDpiChanged);
	display->OrientationChanged += ref new TypedEventHandler<DisplayInformation^, Object^>(
		this, &DirectXPage::OnOrientationChanged);
	DisplayInformation::DisplayContentsInvalidated +=
		ref new TypedEventHandler<DisplayInformation^, Object^>(
			this, &DirectXPage::OnDisplayContentsInvalidated);
	swapChainPanel->CompositionScaleChanged +=
		ref new TypedEventHandler<SwapChainPanel^, Object^>(
			this, &DirectXPage::OnCompositionScaleChanged);
	swapChainPanel->SizeChanged += ref new SizeChangedEventHandler(
		this, &DirectXPage::OnSwapChainPanelSizeChanged);

	m_deviceResources = std::make_shared<DX::DeviceResources>();
	m_deviceResources->SetSwapChainPanel(swapChainPanel);
	m_main = std::make_unique<cxbx_UWP_HostMain>(m_deviceResources);
	m_main->SetUiCallback([this](const std::wstring& message, bool error) {
		auto copy = std::make_shared<std::wstring>(message);
		Dispatcher->RunAsync(CoreDispatcherPriority::Normal, ref new DispatchedHandler(
			[this, copy, error]() {
				AppendLog(*copy, error);
				statusText->Text = ref new String(copy->c_str());
				UpdateButtons();
			}));
	});
	RestoreLastTitle();
	UpdateButtons();
}

DirectXPage::~DirectXPage()
{
	if (m_main) {
		m_main->SetUiCallback(nullptr);
	}
}

void DirectXPage::RestoreLastTitle()
{
	auto list = StorageApplicationPermissions::FutureAccessList;
	auto token = ref new String(LastTitleToken);
	if (!list->ContainsItem(token)) {
		return;
	}
	create_task(list->GetFileAsync(token)).then([this, token](task<StorageFile^> operation) {
		try {
			SelectTitle(operation.get());
		}
		catch (...) {
			StorageApplicationPermissions::FutureAccessList->Remove(token);
		}
	});
}

void DirectXPage::SelectTitle(StorageFile^ file)
{
	if (!file) {
		return;
	}
	m_selectedTitle = file;
	titleText->Text = file->Name;
	statusText->Text = L"Título brokered pronto para iniciar";
	StorageApplicationPermissions::FutureAccessList->AddOrReplace(ref new String(LastTitleToken), file);
	AppendLog(L"Selecionado: " + std::wstring(file->Name->Data()), false);
	UpdateButtons();
}

void DirectXPage::SelectTitle_Click(Object^, RoutedEventArgs^)
{
	if (m_main->IsRunning()) {
		AppendLog(L"Pare a sessão atual antes de selecionar outro título.", true);
		return;
	}
	auto picker = ref new FileOpenPicker();
	picker->ViewMode = PickerViewMode::List;
	picker->SuggestedStartLocation = PickerLocationId::ComputerFolder;
	picker->FileTypeFilter->Append(L".xbe");
	create_task(picker->PickSingleFileAsync()).then([this](StorageFile^ file) {
		if (file) {
			SelectTitle(file);
		}
	});
}

void DirectXPage::Start_Click(Object^, RoutedEventArgs^)
{
	if (!m_selectedTitle) {
		AppendLog(L"Selecione um arquivo XBE primeiro.", true);
		return;
	}
	selectTitleButton->IsEnabled = false;
	startButton->IsEnabled = false;
	stopButton->IsEnabled = true;
	controlPanel->Opacity = 0.82;
	create_task(m_main->StartAsync(m_selectedTitle)).then([this](bool started) {
		Dispatcher->RunAsync(CoreDispatcherPriority::Normal, ref new DispatchedHandler([this, started]() {
			if (started) {
				controlPanel->Opacity = 0.35;
			}
			UpdateButtons();
		}));
	});
}

void DirectXPage::Stop_Click(Object^, RoutedEventArgs^)
{
	stopButton->IsEnabled = false;
	create_task(m_main->StopAsync()).then([this]() {
		Dispatcher->RunAsync(CoreDispatcherPriority::Normal, ref new DispatchedHandler([this]() {
			controlPanel->Opacity = 1.0;
			UpdateButtons();
		}));
	});
}

void DirectXPage::AppendLog(const std::wstring& message, bool error)
{
	std::wstring current = logText->Text ? logText->Text->Data() : L"";
	if (current.size() > 48000) {
		current.erase(0, current.size() - 32000);
	}
	current += error ? L"[ERRO] " : L"";
	current += message;
	current += L"\r\n";
	logText->Text = ref new String(current.c_str());
	logScroller->ChangeView(nullptr, logScroller->ScrollableHeight, nullptr, true);
}

void DirectXPage::UpdateButtons()
{
	const bool running = m_main && m_main->IsRunning();
	selectTitleButton->IsEnabled = !running;
	startButton->IsEnabled = !running && m_selectedTitle != nullptr;
	stopButton->IsEnabled = running;
}

IAsyncAction^ DirectXPage::SuspendAsync()
{
	// UWP can suspend/deactivate the app around pickers, dialogs and ordinary
	// lifecycle transitions. Suspending the process already freezes its
	// threads; destroying the embedded core here turned those transitions into
	// an unsolicited user-visible Stop. Preserve the session and only release
	// discardable D3D allocations. Explicit Stop and host destruction still
	// perform the full RequestStop/Destroy sequence.
	return create_async([resources = m_deviceResources]() {
		resources->Trim();
	});
}

void DirectXPage::SaveInternalState(IPropertySet^)
{
	// State persistence must not terminate an active emulation session.
}

void DirectXPage::LoadInternalState(IPropertySet^)
{
	statusText->Text = L"Retomado. Inicie o título novamente.";
	UpdateButtons();
}

void DirectXPage::OnVisibilityChanged(CoreWindow^, VisibilityChangedEventArgs^ args)
{
	m_windowVisible = args->Visible;
}

void DirectXPage::OnDpiChanged(DisplayInformation^ sender, Object^)
{
	if (!m_main->CanResize()) return;
	critical_section::scoped_lock lock(m_main->GetCriticalSection());
	m_deviceResources->SetDpi(sender->LogicalDpi);
}

void DirectXPage::OnOrientationChanged(DisplayInformation^ sender, Object^)
{
	if (!m_main->CanResize()) return;
	critical_section::scoped_lock lock(m_main->GetCriticalSection());
	m_deviceResources->SetCurrentOrientation(sender->CurrentOrientation);
}

void DirectXPage::OnDisplayContentsInvalidated(DisplayInformation^, Object^)
{
	if (!m_main->CanResize()) return;
	critical_section::scoped_lock lock(m_main->GetCriticalSection());
	m_deviceResources->ValidateDevice();
}

void DirectXPage::OnCompositionScaleChanged(SwapChainPanel^ sender, Object^)
{
	if (!m_main->CanResize()) return;
	critical_section::scoped_lock lock(m_main->GetCriticalSection());
	m_deviceResources->SetCompositionScale(sender->CompositionScaleX, sender->CompositionScaleY);
}

void DirectXPage::OnSwapChainPanelSizeChanged(Object^, SizeChangedEventArgs^ args)
{
	if (!m_main->CanResize()) return;
	critical_section::scoped_lock lock(m_main->GetCriticalSection());
	m_deviceResources->SetLogicalSize(args->NewSize);
}
