#include "UwpEmulatorSession.h"
#include "..\..\hle\D3D8\Rendering\UwpD3D11Host.h"

#include <mutex>
#include <string>

static_assert(sizeof(void*) == 8, "The UWP emulator session is x64-only.");

namespace
{
	struct ExecutorRegistry
	{
		std::mutex mutex;
		CxbxUwpCoreExecutor executor = {};
	};

	ExecutorRegistry& GetExecutorRegistry()
	{
		// Function-local construction makes provider registration safe even when
		// it is triggered by a static initializer in another translation unit.
		static ExecutorRegistry registry;
		return registry;
	}

	CxbxUwpCoreExecutor ExecutorSnapshot()
	{
		auto& registry = GetExecutorRegistry();
		std::lock_guard<std::mutex> lock(registry.mutex);
		return registry.executor;
	}
}

struct CxbxUwpEmulatorSession::Impl
{
	mutable std::mutex mutex;
	CxbxUwpSessionState state = CxbxUwpSessionState::Idle;
	HRESULT result = S_OK;
	CxbxUwpSessionCallback callback = nullptr;
	void* callbackContext = nullptr;
	std::wstring message;
};

HRESULT CxbxUwpRegisterCoreExecutor(const CxbxUwpCoreExecutor* executor)
{
	auto& registry = GetExecutorRegistry();
	std::lock_guard<std::mutex> lock(registry.mutex);
	if (!executor) {
		registry.executor = {};
		return S_OK;
	}
	if (executor->size < sizeof(CxbxUwpCoreExecutor) ||
		executor->abiVersion != CXBXR_UWP_EXECUTOR_ABI_VERSION ||
		!executor->boot || !executor->pause || !executor->resume || !executor->stop) {
		return E_INVALIDARG;
	}
	registry.executor = *executor;
	return S_OK;
}

bool CxbxUwpHasCoreExecutor()
{
	return ExecutorSnapshot().boot != nullptr;
}

CxbxUwpEmulatorSession::CxbxUwpEmulatorSession() : m_impl(new Impl) {}

CxbxUwpEmulatorSession::~CxbxUwpEmulatorSession()
{
	if (State() == CxbxUwpSessionState::Running || State() == CxbxUwpSessionState::Paused) Stop();
	delete m_impl;
}

void CxbxUwpEmulatorSession::SetCallback(CxbxUwpSessionCallback callback, void* context)
{
	std::lock_guard<std::mutex> lock(m_impl->mutex);
	m_impl->callback = callback;
	m_impl->callbackContext = context;
}

void CxbxUwpEmulatorSession::Transition(CxbxUwpSessionState state, HRESULT result, const wchar_t* message)
{
	CxbxUwpSessionCallback callback;
	void* context;
	std::wstring stableMessage;
	{
		std::lock_guard<std::mutex> lock(m_impl->mutex);
		m_impl->state = state;
		m_impl->result = result;
		m_impl->message = message ? message : L"";
		callback = m_impl->callback;
		context = m_impl->callbackContext;
		stableMessage = m_impl->message;
	}
	if (callback) callback(state, result, stableMessage.c_str(), context);
}

HRESULT CxbxUwpEmulatorSession::Start(const CxbxUwpBootConfig& config)
{
	auto current = State();
	if (current == CxbxUwpSessionState::Starting || current == CxbxUwpSessionState::Running ||
		current == CxbxUwpSessionState::Paused || current == CxbxUwpSessionState::Stopping) return E_ILLEGAL_METHOD_CALL;
	if (config.size < sizeof(CxbxUwpBootConfig) || !config.gamePath || !*config.gamePath ||
		!config.dataRoot || !*config.dataRoot || !config.logPath || !*config.logPath ||
		!config.gameRoot || !*config.gameRoot) {
		Transition(CxbxUwpSessionState::Failed, E_INVALIDARG, L"Configuração de boot incompleta.");
		return E_INVALIDARG;
	}

	Transition(CxbxUwpSessionState::Starting, S_OK, L"Preparando sessão in-process…");
	CxbxUwpD3D11Surface surface = {};
	HRESULT result = CxbxUwpAcquireD3D11Surface(&surface);
	if (FAILED(result)) {
		Transition(CxbxUwpSessionState::Failed, result, L"A superfície Backend_D3D11 não está registrada.");
		return result;
	}
	CxbxUwpReleaseD3D11Surface(&surface);

	auto executor = ExecutorSnapshot();
	if (!executor.boot) {
		result = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
		Transition(CxbxUwpSessionState::Failed, result,
			L"O host UWP x64 está pronto, mas nenhum executor CPU Xbox x86-em-x64 foi registrado.");
		return result;
	}

	result = executor.boot(&config);
	if (FAILED(result)) {
		Transition(CxbxUwpSessionState::Failed, result, L"O executor recusou o boot do título.");
		return result;
	}
	Transition(CxbxUwpSessionState::Running, S_OK, L"Emulação em execução.");
	return S_OK;
}

HRESULT CxbxUwpEmulatorSession::Pause()
{
	if (State() != CxbxUwpSessionState::Running) return E_ILLEGAL_METHOD_CALL;
	auto executor = ExecutorSnapshot();
	HRESULT result = executor.pause ? executor.pause() : HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
	if (SUCCEEDED(result)) Transition(CxbxUwpSessionState::Paused, result, L"Emulação pausada.");
	return result;
}

HRESULT CxbxUwpEmulatorSession::Resume()
{
	if (State() != CxbxUwpSessionState::Paused) return E_ILLEGAL_METHOD_CALL;
	auto executor = ExecutorSnapshot();
	HRESULT result = executor.resume ? executor.resume() : HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
	if (SUCCEEDED(result)) Transition(CxbxUwpSessionState::Running, result, L"Emulação retomada.");
	return result;
}

HRESULT CxbxUwpEmulatorSession::Stop()
{
	auto current = State();
	if (current != CxbxUwpSessionState::Running && current != CxbxUwpSessionState::Paused) return S_FALSE;
	Transition(CxbxUwpSessionState::Stopping, S_OK, L"Encerrando emulação…");
	auto executor = ExecutorSnapshot();
	HRESULT result = executor.stop ? executor.stop() : HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
	Transition(SUCCEEDED(result) ? CxbxUwpSessionState::Stopped : CxbxUwpSessionState::Failed,
		result, SUCCEEDED(result) ? L"Emulação encerrada." : L"Falha ao encerrar o executor.");
	return result;
}

CxbxUwpSessionState CxbxUwpEmulatorSession::State() const
{
	std::lock_guard<std::mutex> lock(m_impl->mutex);
	return m_impl->state;
}

HRESULT CxbxUwpEmulatorSession::LastResult() const
{
	std::lock_guard<std::mutex> lock(m_impl->mutex);
	return m_impl->result;
}
