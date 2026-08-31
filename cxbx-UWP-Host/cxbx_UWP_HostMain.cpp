#include "pch.h"
#include "cxbx_UWP_HostMain.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <thread>

using namespace cxbx_UWP_Host;
using namespace Concurrency;
using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Storage;
using namespace Windows::Storage::Streams;
using namespace Windows::UI::Core;
using namespace Windows::UI::Popups;

namespace
{
	std::wstring Utf8ToWide(const char* value)
	{
		if (!value || !*value) {
			return {};
		}
		const int length = MultiByteToWideChar(CP_UTF8, 0, value, -1, nullptr, 0);
		if (length <= 1) {
			return {};
		}
		std::wstring result(static_cast<size_t>(length), L'\0');
		MultiByteToWideChar(CP_UTF8, 0, value, -1, result.data(), length);
		result.resize(static_cast<size_t>(length - 1));
		return result;
	}

	std::string WideToUtf8(String^ value)
	{
		if (!value || value->IsEmpty()) {
			return {};
		}
		const wchar_t* text = value->Data();
		const int length = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
		if (length <= 1) {
			return {};
		}
		std::string result(static_cast<size_t>(length), '\0');
		WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), length, nullptr, nullptr);
		result.resize(static_cast<size_t>(length - 1));
		return result;
	}

	const wchar_t* StateText(CxbxEmbedState state)
	{
		switch (state) {
		case CXBX_EMBED_STATE_CREATED: return L"Criado";
		case CXBX_EMBED_STATE_INITIALIZING: return L"Inicializando";
		case CXBX_EMBED_STATE_READY: return L"Pronto";
		case CXBX_EMBED_STATE_RUNNING: return L"Executando";
		case CXBX_EMBED_STATE_STOPPING: return L"Parando";
		case CXBX_EMBED_STATE_STOPPED: return L"Parado";
		case CXBX_EMBED_STATE_FAILED: return L"Falhou";
		default: return L"Desconhecido";
		}
	}

	std::wstring Win32ErrorMessage(DWORD code)
	{
		wchar_t* buffer = nullptr;
		const DWORD count = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0,
			reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
		std::wstring result = count && buffer ? std::wstring(buffer, count) : L"erro desconhecido";
		if (buffer) {
			LocalFree(buffer);
		}
		return result;
	}

	void AddPromptCommand(MessageDialog^ dialog, const wchar_t* label,
		CxbxEmbedPromptResult result)
	{
		dialog->Commands->Append(ref new UICommand(ref new String(label), nullptr,
			PropertyValue::CreateInt32(static_cast<int>(result))));
	}
}

cxbx_UWP_HostMain::cxbx_UWP_HostMain(const std::shared_ptr<DX::DeviceResources>& deviceResources)
	: m_deviceResources(deviceResources),
	  m_dispatcher(Windows::UI::Xaml::Window::Current->Dispatcher),
	  m_status(L"Selecione um arquivo XBE")
{
	m_deviceResources->RegisterDeviceNotify(this);
	const auto localFolder = ApplicationData::Current->LocalFolder;
	const auto cacheFolder = ApplicationData::Current->LocalCacheFolder;
	m_localDataPath = WideToUtf8(localFolder->Path);
	m_cachePath = WideToUtf8(cacheFolder->Path);
	const std::filesystem::path logPath(localFolder->Path->Data());
	m_logFile.open(logPath / L"cxbx-host.log", std::ios::binary | std::ios::trunc);
	if (m_logFile.is_open()) {
		// Make the encoding unambiguous to Notepad and Windows PowerShell, and
		// discard mojibake left by builds compiled without /utf-8.
		static constexpr unsigned char utf8Bom[] = { 0xEF, 0xBB, 0xBF };
		m_logFile.write(reinterpret_cast<const char*>(utf8Bom), sizeof(utf8Bom));
	}
	AppendLogLine(L"=== cxbx-UWP-Host iniciado ===");
}

cxbx_UWP_HostMain::~cxbx_UWP_HostMain()
{
	std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);
	StopAndDestroy();
	UnloadCore();
	m_deviceResources->RegisterDeviceNotify(nullptr);
}

void cxbx_UWP_HostMain::SetUiCallback(UiCallback callback)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_uiCallback = std::move(callback);
}

task<bool> cxbx_UWP_HostMain::StartAsync(StorageFile^ titleFile)
{
	if (!titleFile) {
		SetStatus(L"Nenhum arquivo XBE foi selecionado.", true);
		return task_from_result(false);
	}
	if (IsRunning() || m_stopping.load()) {
		SetStatus(L"Já existe uma sessão ativa ou sendo encerrada.", true);
		return task_from_result(false);
	}

	SetStatus(L"Carregando cxbxr-emu.dll...");
	return create_task([this, titleFile]() {
		std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);
		std::wstring error;
		const bool started = !m_stopping.load() && CreateAndLaunch(titleFile, error);
		if (!started) {
			SetStatus(error.empty() ? L"Não foi possível iniciar o Cxbx." : error, true);
			StopAndDestroy();
		}
		return started;
	});
}

task<void> cxbx_UWP_HostMain::StopAsync()
{
	if (m_stopping.exchange(true)) {
		return task_from_result();
	}
	SetStatus(L"Solicitando parada...");
	return create_task([this]() {
		std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);
		StopAndDestroy();
		m_stopping.store(false);
		SetStatus(L"Parado. É possível iniciar outro título.");
	});
}

bool cxbx_UWP_HostMain::IsRunning() const
{
	std::lock_guard<std::mutex> lock(m_mutex);
	// A failed/stopped instance must still be explicitly destroyed before a
	// new singleton core can be created. Keep Stop enabled until that happens.
	return m_instance != nullptr;
}

bool cxbx_UWP_HostMain::CanResize() const
{
	return !IsRunning() && !m_stopping.load();
}

std::wstring cxbx_UWP_HostMain::StatusText() const
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_status;
}

bool cxbx_UWP_HostMain::LoadCore(std::wstring& error)
{
	if (m_module) {
		return true;
	}
	m_module = LoadPackagedLibrary(L"cxbxr-emu.dll", 0);
	if (!m_module) {
		const DWORD code = GetLastError();
		std::wstringstream stream;
		stream << L"LoadPackagedLibrary(cxbxr-emu.dll) falhou: " << code << L" ("
			<< Win32ErrorMessage(code) << L")";
		error = stream.str();
		return false;
	}

#define CXBX_RESOLVE(member, name) \
	member = reinterpret_cast<decltype(member)>(GetProcAddress(m_module, name)); \
	if (!member) { error = L"A DLL não exporta " L##name L" (ABI v4 requerida)."; UnloadCore(); return false; }
	CXBX_RESOLVE(m_create, "CxbxEmbed_Create");
	CXBX_RESOLVE(m_initialize, "CxbxEmbed_InitializeAsync");
	CXBX_RESOLVE(m_launch, "CxbxEmbed_Launch");
	CXBX_RESOLVE(m_requestStop, "CxbxEmbed_RequestStop");
	CXBX_RESOLVE(m_getState, "CxbxEmbed_GetState");
	CXBX_RESOLVE(m_destroy, "CxbxEmbed_Destroy");
#undef CXBX_RESOLVE
	Notify(L"cxbxr-emu.dll carregada; ABI de embedding v4 resolvida.");
	return true;
}

void cxbx_UWP_HostMain::UnloadCore()
{
	if (m_module) {
		FreeLibrary(m_module);
	}
	m_module = nullptr;
	m_create = nullptr;
	m_initialize = nullptr;
	m_launch = nullptr;
	m_requestStop = nullptr;
	m_getState = nullptr;
	m_destroy = nullptr;
}

bool cxbx_UWP_HostMain::CreateAndLaunch(StorageFile^ titleFile, std::wstring& error)
{
	if (!LoadCore(error)) {
		return false;
	}
	ID3D11Texture2D* backBuffer = m_deviceResources->GetBackBuffer();
	if (!backBuffer) {
		error = L"O SwapChainPanel ainda não possui um backbuffer D3D11.";
		return false;
	}
	D3D11_TEXTURE2D_DESC backBufferDesc{};
	backBuffer->GetDesc(&backBufferDesc);
	if (!backBufferDesc.Width || !backBufferDesc.Height) {
		error = L"O backbuffer D3D11 fornecido pelo host tem tamanho inválido.";
		return false;
	}

	{
		std::lock_guard<std::mutex> lock(m_storageMutex);
		m_storage.clear();
		m_nextStorageHandle = 1;
	}
	m_titleHandle = RegisterFile(titleFile, false);

	CxbxEmbedCallbacks callbacks{};
	callbacks.struct_size = sizeof(callbacks);
	callbacks.abi_version = CXBX_EMBED_CALLBACKS_VERSION;
	callbacks.user_data = this;
	callbacks.log = &LogCallback;
	callbacks.error = &ErrorCallback;
	callbacks.state_changed = &StateCallback;
	callbacks.prompt = &PromptCallback;
	callbacks.host_event = &HostEventCallback;

	CxbxEmbedConfig config{};
	config.struct_size = sizeof(config);
	config.abi_version = CXBX_EMBED_ABI_VERSION;
	config.local_data_path_utf8 = m_localDataPath.c_str();
	config.cache_path_utf8 = m_cachePath.c_str();
	config.cpu_backend_module_utf8 = "qemu-cxbx-i386.dll";
	config.d3d11_presentation.struct_size = sizeof(config.d3d11_presentation);
	config.d3d11_presentation.abi_version = CXBX_EMBED_D3D11_PRESENTATION_VERSION;
	config.d3d11_presentation.user_data = this;
	config.d3d11_presentation.d3d11_device = m_deviceResources->GetD3DDevice();
	config.d3d11_presentation.d3d11_context = m_deviceResources->GetD3DDeviceContext();
	config.d3d11_presentation.render_target = backBuffer;
	config.d3d11_presentation.width = backBufferDesc.Width;
	config.d3d11_presentation.height = backBufferDesc.Height;
	config.d3d11_presentation.present = &PresentCallback;
	config.brokered_storage.struct_size = sizeof(config.brokered_storage);
	config.brokered_storage.abi_version = CXBX_EMBED_STORAGE_VERSION;
	config.brokered_storage.user_data = this;
	config.brokered_storage.title_file = m_titleHandle;
	config.brokered_storage.get_size = &StorageGetSize;
	config.brokered_storage.read_at = &StorageReadAt;
	config.brokered_storage.open_relative = &StorageOpenRelative;
	config.brokered_storage.close = &StorageClose;

	CxbxEmbedInstance* instance = nullptr;
	CxbxEmbedResult result = m_create(&config, &callbacks, &instance);
	if (result != CXBX_EMBED_OK || !instance) {
		std::wstringstream stream;
		stream << L"CxbxEmbed_Create falhou com código " << static_cast<int>(result) << L".";
		error = stream.str();
		return false;
	}
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_instance = instance;
	}

	result = m_initialize(instance);
	if (result != CXBX_EMBED_OK) {
		error = L"CxbxEmbed_InitializeAsync rejeitou a inicialização.";
		return false;
	}

	for (unsigned attempt = 0; attempt < 1000; ++attempt) {
		const auto state = m_getState(instance);
		if (state == CXBX_EMBED_STATE_READY) {
			break;
		}
		if (state == CXBX_EMBED_STATE_FAILED || state == CXBX_EMBED_STATE_STOPPED) {
			error = L"A inicialização do núcleo falhou antes do lançamento.";
			return false;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	if (m_getState(instance) != CXBX_EMBED_STATE_READY) {
		error = L"Tempo esgotado aguardando o núcleo ficar pronto.";
		return false;
	}
	if (m_stopping.load()) {
		error = L"A inicialização foi cancelada pelo host.";
		return false;
	}

	result = m_launch(instance);
	if (result != CXBX_EMBED_OK) {
		error = L"CxbxEmbed_Launch rejeitou o lançamento.";
		return false;
	}
	SetStatus(L"Cxbx em execução: " + std::wstring(titleFile->Name->Data()));
	return true;
}

void cxbx_UWP_HostMain::StopAndDestroy()
{
	CxbxEmbedInstance* instance = nullptr;
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		instance = m_instance;
		m_instance = nullptr;
	}
	if (instance && m_getState && m_requestStop && m_destroy) {
		const auto state = m_getState(instance);
		if (state == CXBX_EMBED_STATE_INITIALIZING || state == CXBX_EMBED_STATE_READY ||
			state == CXBX_EMBED_STATE_RUNNING) {
			m_requestStop(instance);
		}
		m_destroy(instance);
	}
	{
		std::lock_guard<std::mutex> lock(m_storageMutex);
		m_storage.clear();
		m_titleHandle = CXBX_EMBED_INVALID_STORAGE_HANDLE;
	}
}

void cxbx_UWP_HostMain::Notify(const std::wstring& message, bool error)
{
	AppendLogLine(message);
	UiCallback callback;
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		callback = m_uiCallback;
	}
	if (callback) {
		callback(message, error);
	}
}

void cxbx_UWP_HostMain::SetStatus(const std::wstring& status, bool error)
{
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_status = status;
	}
	Notify(status, error);
}

void cxbx_UWP_HostMain::AppendLogLine(const std::wstring& line)
{
	std::lock_guard<std::mutex> lock(m_logMutex);
	if (!m_logFile.is_open()) {
		return;
	}
	const int length = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (length > 1) {
		std::string utf8(static_cast<size_t>(length), '\0');
		WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, utf8.data(), length, nullptr, nullptr);
		utf8.resize(static_cast<size_t>(length - 1));
		m_logFile << utf8 << "\r\n";
		m_logFile.flush();
	}
}

CxbxEmbedStorageHandle cxbx_UWP_HostMain::RegisterFile(StorageFile^ file, bool closeable)
{
	if (!file) {
		return CXBX_EMBED_INVALID_STORAGE_HANDLE;
	}
	std::lock_guard<std::mutex> lock(m_storageMutex);
	const auto handle = m_nextStorageHandle++;
	m_storage.emplace(handle, StorageEntry{ file, nullptr, closeable });
	return handle;
}

CxbxEmbedStorageHandle cxbx_UWP_HostMain::RegisterFolder(StorageFolder^ folder, bool closeable)
{
	if (!folder) {
		return CXBX_EMBED_INVALID_STORAGE_HANDLE;
	}
	std::lock_guard<std::mutex> lock(m_storageMutex);
	const auto handle = m_nextStorageHandle++;
	m_storage.emplace(handle, StorageEntry{ nullptr, folder, closeable });
	return handle;
}

cxbx_UWP_HostMain::StorageEntry cxbx_UWP_HostMain::FindStorage(CxbxEmbedStorageHandle handle) const
{
	std::lock_guard<std::mutex> lock(m_storageMutex);
	const auto found = m_storage.find(handle);
	return found == m_storage.end() ? StorageEntry{} : found->second;
}

void CXBX_EMBED_CALL cxbx_UWP_HostMain::LogCallback(void* userData, CxbxEmbedLogLevel level,
	const char* moduleUtf8, const char* messageUtf8)
{
	auto* host = static_cast<cxbx_UWP_HostMain*>(userData);
	std::wstring line = L"[" + Utf8ToWide(moduleUtf8) + L"] " + Utf8ToWide(messageUtf8);
	host->Notify(line, level >= CXBX_EMBED_LOG_ERROR);
}

void CXBX_EMBED_CALL cxbx_UWP_HostMain::ErrorCallback(void* userData, CxbxEmbedResult,
	const char* messageUtf8)
{
	static_cast<cxbx_UWP_HostMain*>(userData)->SetStatus(Utf8ToWide(messageUtf8), true);
}

void CXBX_EMBED_CALL cxbx_UWP_HostMain::StateCallback(void* userData, CxbxEmbedState state)
{
	auto* host = static_cast<cxbx_UWP_HostMain*>(userData);
	host->Notify(L"Estado do núcleo: " + std::wstring(StateText(state)), state == CXBX_EMBED_STATE_FAILED);
}

CxbxEmbedPromptResult CXBX_EMBED_CALL cxbx_UWP_HostMain::PromptCallback(void* userData,
	CxbxEmbedPromptIcon, CxbxEmbedPromptButtons buttons,
	CxbxEmbedPromptResult defaultResult, const char* messageUtf8)
{
	return static_cast<cxbx_UWP_HostMain*>(userData)->ShowPrompt(
		buttons, defaultResult, Utf8ToWide(messageUtf8));
}

void CXBX_EMBED_CALL cxbx_UWP_HostMain::HostEventCallback(void* userData,
	CxbxEmbedHostEvent event, uint64_t value)
{
	std::wstringstream stream;
	stream << L"Evento do núcleo " << static_cast<unsigned>(event) << L": " << value;
	static_cast<cxbx_UWP_HostMain*>(userData)->Notify(stream.str());
}

void CXBX_EMBED_CALL cxbx_UWP_HostMain::PresentCallback(void* userData, void*, uint32_t, uint32_t)
{
	auto* host = static_cast<cxbx_UWP_HostMain*>(userData);
	try {
		host->m_deviceResources->Present(false);
	}
	catch (Exception^ error) {
		host->SetStatus(L"Falha ao apresentar o quadro: " + std::wstring(error->Message->Data()), true);
	}
}

CxbxEmbedStorageResult CXBX_EMBED_CALL cxbx_UWP_HostMain::StorageGetSize(void* userData,
	CxbxEmbedStorageHandle file, uint64_t* sizeOut)
{
	if (!sizeOut) {
		return CXBX_EMBED_STORAGE_IO_ERROR;
	}
	const auto entry = static_cast<cxbx_UWP_HostMain*>(userData)->FindStorage(file);
	if (!entry.file) {
		return CXBX_EMBED_STORAGE_INVALID_HANDLE;
	}
	try {
		*sizeOut = create_task(entry.file->GetBasicPropertiesAsync()).get()->Size;
		return CXBX_EMBED_STORAGE_OK;
	}
	catch (Exception^ error) {
		return error->HResult == E_ACCESSDENIED ? CXBX_EMBED_STORAGE_ACCESS_DENIED :
			CXBX_EMBED_STORAGE_IO_ERROR;
	}
}

CxbxEmbedStorageResult CXBX_EMBED_CALL cxbx_UWP_HostMain::StorageReadAt(void* userData,
	CxbxEmbedStorageHandle file, uint64_t offset, void* buffer,
	uint32_t bytesRequested, uint32_t* bytesReadOut)
{
	if (!buffer || !bytesReadOut) {
		return CXBX_EMBED_STORAGE_IO_ERROR;
	}
	*bytesReadOut = 0;
	const auto entry = static_cast<cxbx_UWP_HostMain*>(userData)->FindStorage(file);
	if (!entry.file) {
		return CXBX_EMBED_STORAGE_INVALID_HANDLE;
	}
	try {
		auto stream = create_task(entry.file->OpenAsync(FileAccessMode::Read)).get();
		if (offset >= stream->Size) {
			return CXBX_EMBED_STORAGE_OK;
		}
		auto reader = ref new DataReader(stream->GetInputStreamAt(offset));
		reader->InputStreamOptions = InputStreamOptions::Partial;
		const unsigned available = static_cast<unsigned>((std::min)(
			static_cast<uint64_t>(bytesRequested), stream->Size - offset));
		const unsigned loaded = create_task(reader->LoadAsync(available)).get();
		auto data = ref new Array<unsigned char>(loaded);
		reader->ReadBytes(data);
		std::memcpy(buffer, data->Data, loaded);
		reader->DetachStream();
		*bytesReadOut = loaded;
		return CXBX_EMBED_STORAGE_OK;
	}
	catch (Exception^ error) {
		return error->HResult == E_ACCESSDENIED ? CXBX_EMBED_STORAGE_ACCESS_DENIED :
			CXBX_EMBED_STORAGE_IO_ERROR;
	}
}

CxbxEmbedStorageResult CXBX_EMBED_CALL cxbx_UWP_HostMain::StorageOpenRelative(void* userData,
	CxbxEmbedStorageHandle folder, const char* relativePathUtf8,
	uint32_t access, CxbxEmbedStorageHandle* fileOut)
{
	if (!fileOut || !relativePathUtf8 || (access & CXBX_EMBED_STORAGE_WRITE)) {
		return CXBX_EMBED_STORAGE_NOT_SUPPORTED;
	}
	*fileOut = CXBX_EMBED_INVALID_STORAGE_HANDLE;
	auto* host = static_cast<cxbx_UWP_HostMain*>(userData);
	const auto entry = host->FindStorage(folder);
	if (!entry.folder) {
		return CXBX_EMBED_STORAGE_INVALID_HANDLE;
	}
	try {
		const std::wstring relative = Utf8ToWide(relativePathUtf8);
		if (relative.empty() || relative.find(L"..") != std::wstring::npos ||
			relative.front() == L'/' || relative.front() == L'\\') {
			return CXBX_EMBED_STORAGE_ACCESS_DENIED;
		}
		auto file = create_task(entry.folder->GetFileAsync(ref new String(relative.c_str()))).get();
		*fileOut = host->RegisterFile(file, true);
		return CXBX_EMBED_STORAGE_OK;
	}
	catch (Exception^ error) {
		if (error->HResult == E_ACCESSDENIED) {
			return CXBX_EMBED_STORAGE_ACCESS_DENIED;
		}
		return error->HResult == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ?
			CXBX_EMBED_STORAGE_NOT_FOUND : CXBX_EMBED_STORAGE_IO_ERROR;
	}
}

void CXBX_EMBED_CALL cxbx_UWP_HostMain::StorageClose(void* userData, CxbxEmbedStorageHandle file)
{
	auto* host = static_cast<cxbx_UWP_HostMain*>(userData);
	std::lock_guard<std::mutex> lock(host->m_storageMutex);
	const auto found = host->m_storage.find(file);
	if (found != host->m_storage.end() && found->second.closeable) {
		host->m_storage.erase(found);
	}
}

CxbxEmbedPromptResult cxbx_UWP_HostMain::ShowPrompt(CxbxEmbedPromptButtons buttons,
	CxbxEmbedPromptResult defaultResult, const std::wstring& message)
{
	auto completion = std::make_shared<task_completion_event<CxbxEmbedPromptResult>>();
	m_dispatcher->RunAsync(CoreDispatcherPriority::Normal, ref new DispatchedHandler(
		[this, completion, buttons, defaultResult, message]() {
			auto dialog = ref new MessageDialog(ref new String(message.c_str()), L"Cxbx-Reloaded");
			if (buttons == CXBX_EMBED_PROMPT_BUTTONS_YES_NO ||
				buttons == CXBX_EMBED_PROMPT_BUTTONS_YES_NO_CANCEL) {
				AddPromptCommand(dialog, L"Sim", CXBX_EMBED_PROMPT_YES);
				AddPromptCommand(dialog, L"Não", CXBX_EMBED_PROMPT_NO);
				if (buttons == CXBX_EMBED_PROMPT_BUTTONS_YES_NO_CANCEL) {
					AddPromptCommand(dialog, L"Cancelar", CXBX_EMBED_PROMPT_CANCEL);
				}
			}
			else {
				AddPromptCommand(dialog, L"OK", CXBX_EMBED_PROMPT_OK);
				if (buttons != CXBX_EMBED_PROMPT_BUTTONS_OK) {
					AddPromptCommand(dialog, L"Cancelar", CXBX_EMBED_PROMPT_CANCEL);
				}
			}
			create_task(dialog->ShowAsync()).then([completion, defaultResult](IUICommand^ command) {
				CxbxEmbedPromptResult result = defaultResult;
				if (command && command->Id) {
					result = static_cast<CxbxEmbedPromptResult>(
						safe_cast<IPropertyValue^>(command->Id)->GetInt32());
				}
				completion->set(result);
			});
		}));
	return create_task(*completion).get();
}

void cxbx_UWP_HostMain::OnDeviceLost()
{
	SetStatus(L"Dispositivo D3D11 perdido; encerrando a sessão.", true);
	CxbxEmbedInstance* instance = nullptr;
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		instance = m_instance;
	}
	if (instance && m_requestStop) {
		const auto state = m_getState(instance);
		if (state == CXBX_EMBED_STATE_INITIALIZING || state == CXBX_EMBED_STATE_READY ||
			state == CXBX_EMBED_STATE_RUNNING) {
			m_requestStop(instance);
		}
	}
}

void cxbx_UWP_HostMain::OnDeviceRestored()
{
	SetStatus(L"Dispositivo D3D11 restaurado. Inicie o título novamente.");
}
