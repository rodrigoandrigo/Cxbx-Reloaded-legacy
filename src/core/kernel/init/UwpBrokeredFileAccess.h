#pragma once

#include <Windows.h>

#include <cstdint>
#include <vector>

// Native boundary between the UWP picker/storage broker and the emulated Xbox
// kernel.  The core deliberately knows nothing about C++/CX StorageFolder
// objects; the app supplies handles and directory records for the folder that
// the user explicitly authorized.
using CxbxUwpOpenBrokeredFile = HRESULT(__stdcall*)(
	const wchar_t* relativePath, bool directory, std::uint32_t desiredAccess,
	std::uint32_t shareAccess, std::uint32_t disposition, std::uint32_t options,
	HANDLE* handle);

using CxbxUwpEnumerateBrokeredDirectory = HRESULT(__stdcall*)(
	const wchar_t* relativePath, const wchar_t* mask,
	std::vector<WIN32_FIND_DATAW>* entries);

void CxbxUwpRegisterBrokeredFileAccess(
	CxbxUwpOpenBrokeredFile openFile,
	CxbxUwpEnumerateBrokeredDirectory enumerateDirectory);

HRESULT CxbxUwpOpenBrokeredGameFile(
	const wchar_t* relativePath, bool directory, std::uint32_t desiredAccess,
	std::uint32_t shareAccess, std::uint32_t disposition, std::uint32_t options,
	HANDLE* handle);

HRESULT CxbxUwpEnumerateBrokeredGameDirectory(
	const wchar_t* relativePath, const wchar_t* mask,
	std::vector<WIN32_FIND_DATAW>& entries);
