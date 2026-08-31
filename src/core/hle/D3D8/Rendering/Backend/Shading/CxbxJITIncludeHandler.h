// CxbxJITIncludeHandler.h — ID3DInclude that resolves #include directives
// by loading files relative to the emulator executable's "hlsl\" subdirectory.
// Used by both the VS and PS JIT compilers.

#pragma once

#include <d3dcompiler.h>
#include <string>
#include <windows.h>

#ifdef CXBXR_UWP
static std::wstring CxbxJITPathToWide(const std::string& path)
{
    if (path.empty())
        return {};

    const int length = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (length <= 0)
        return {};

    std::wstring wide(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wide.data(), length);
    wide.resize(static_cast<size_t>(length - 1));
    return wide;
}
#endif

class CxbxJITIncludeHandler : public ID3DInclude
{
public:
    CxbxJITIncludeHandler()
    {
        char exePath[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        char* lastSlash = strrchr(exePath, '\\');
        if (lastSlash) *(lastSlash + 1) = '\0';
        m_shaderDir = std::string(exePath) + "hlsl\\";
    }

    STDMETHOD(Open)(D3D_INCLUDE_TYPE /*IncludeType*/, LPCSTR pFileName,
        LPCVOID /*pParentData*/, LPCVOID* ppData, UINT* pBytes) override
    {
        std::string fullPath = m_shaderDir + pFileName;
#ifdef CXBXR_UWP
        const std::wstring widePath = CxbxJITPathToWide(fullPath);
        CREATEFILE2_EXTENDED_PARAMETERS parameters{};
        parameters.dwSize = sizeof(parameters);
        parameters.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
        HANDLE hFile = widePath.empty() ? INVALID_HANDLE_VALUE
            : CreateFile2FromAppW(widePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                OPEN_EXISTING, &parameters);
#else
        HANDLE hFile = CreateFileA(fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
#endif
        if (hFile == INVALID_HANDLE_VALUE)
            return E_FAIL;

        LARGE_INTEGER fileSize64{};
        if (!GetFileSizeEx(hFile, &fileSize64) || fileSize64.QuadPart < 0 ||
            fileSize64.QuadPart > static_cast<LONGLONG>(UINT_MAX)) {
            CloseHandle(hFile);
            return E_FAIL;
        }
        const DWORD fileSize = static_cast<DWORD>(fileSize64.QuadPart);

        char* pData = new (std::nothrow) char[fileSize];
        if (!pData) { CloseHandle(hFile); return E_OUTOFMEMORY; }

        DWORD bytesRead = 0;
        BOOL ok = ReadFile(hFile, pData, fileSize, &bytesRead, nullptr);
        CloseHandle(hFile);
        if (!ok || bytesRead != fileSize) { delete[] pData; return E_FAIL; }

        *ppData = pData;
        *pBytes = bytesRead;
        return S_OK;
    }

    STDMETHOD(Close)(LPCVOID pData) override
    {
        delete[] static_cast<const char*>(pData);
        return S_OK;
    }

private:
    std::string m_shaderDir;
};
