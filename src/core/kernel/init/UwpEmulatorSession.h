#pragma once

#include <Windows.h>
#include <cstdint>

// In-process UWP lifecycle. This ABI deliberately contains no HWND, process
// identifier, command line, shared-memory handle or C++/CX type.
enum class CxbxUwpSessionState : std::uint32_t
{
	Idle,
	Starting,
	Running,
	Paused,
	Stopping,
	Stopped,
	Failed,
};

struct CxbxUwpBootConfig
{
	std::uint32_t size;
	const wchar_t* gamePath;
	const wchar_t* dataRoot;
	const wchar_t* logPath;
	const wchar_t* gameRoot;
	std::uint32_t consoleType; // Auto, retail, devkit or Chihiro.
	std::uint32_t compatibilityFlags;
};

enum CxbxUwpCompatibilityFlags : std::uint32_t
{
	CxbxUwpIgnoreInvalidXbeSignature = 1u << 0,
	CxbxUwpIgnoreInvalidXbeSecurity = 1u << 1,
	CxbxUwpUseAllCores = 1u << 2,
	CxbxUwpSkipRdtscPatching = 1u << 3,
	CxbxUwpDisablePixelShaders = 1u << 4,
};

using CxbxUwpSessionCallback = void(*)(CxbxUwpSessionState state, HRESULT result,
	const wchar_t* message, void* context);

// A CPU executor registers this vtable when it can execute 32-bit Xbox x86
// code inside the x64 UWP process. Backend_D3D11 is obtained independently
// through CxbxUwpAcquireD3D11Surface.
struct CxbxUwpCoreExecutor
{
	std::uint32_t size;
	std::uint32_t abiVersion;
	HRESULT (*boot)(const CxbxUwpBootConfig* config);
	HRESULT (*pause)();
	HRESULT (*resume)();
	HRESULT (*stop)();
};

constexpr std::uint32_t CXBXR_UWP_EXECUTOR_ABI_VERSION = 3;

HRESULT CxbxUwpRegisterCoreExecutor(const CxbxUwpCoreExecutor* executor);
bool CxbxUwpHasCoreExecutor();

class CxbxUwpEmulatorSession final
{
public:
	CxbxUwpEmulatorSession();
	~CxbxUwpEmulatorSession();
	CxbxUwpEmulatorSession(const CxbxUwpEmulatorSession&) = delete;
	CxbxUwpEmulatorSession& operator=(const CxbxUwpEmulatorSession&) = delete;

	void SetCallback(CxbxUwpSessionCallback callback, void* context);
	HRESULT Start(const CxbxUwpBootConfig& config);
	HRESULT Pause();
	HRESULT Resume();
	HRESULT Stop();
	CxbxUwpSessionState State() const;
	HRESULT LastResult() const;

private:
	void Transition(CxbxUwpSessionState state, HRESULT result, const wchar_t* message);
	struct Impl;
	Impl* m_impl;
};
