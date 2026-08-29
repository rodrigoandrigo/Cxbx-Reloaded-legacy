#include "pch.h"
#include "UwpStorageBroker.h"
#include "..\..\src\core\kernel\init\UwpBrokeredFileAccess.h"

#include <cwctype>
#include <string>

using namespace Cxbx_R_uwp;
using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Storage;
using namespace Windows::Storage::AccessCache;
using namespace Windows::Storage::Streams;
using namespace concurrency;
using Microsoft::WRL::ComPtr;

namespace
{
	// WindowsStorageCOM.h also includes the desktop Shell declarations on this
	// SDK/toolset combination.  Only these two Application Family interfaces
	// are required here; declaring their documented ABI locally avoids pulling
	// shobjidl_core.h into the UWP translation unit.
	MIDL_INTERFACE("5CA296B2-2C25-4D22-B785-B885C8201E6A")
	StorageItemHandleAccess : public IUnknown
	{
	public:
		virtual HRESULT STDMETHODCALLTYPE Create(DWORD accessOptions, DWORD sharingOptions,
			DWORD options, IUnknown* oplockBreakingHandler, HANDLE* interopHandle) = 0;
	};

	MIDL_INTERFACE("DF19938F-5462-48A0-BE65-D2A3271A08D6")
	StorageFolderHandleAccess : public IUnknown
	{
	public:
		virtual HRESULT STDMETHODCALLTYPE Create(LPCWSTR fileName, DWORD creationOptions,
			DWORD accessOptions, DWORD sharingOptions, DWORD options,
			IUnknown* oplockBreakingHandler, HANDLE* interopHandle) = 0;
	};

	constexpr DWORD BrokerOptionNone = 0;
	constexpr DWORD BrokerReadAttributes = 0x00000080u;
	constexpr DWORD BrokerRead = 0x00120089u;
	constexpr DWORD BrokerWrite = 0x00120116u;
	constexpr DWORD BrokerShareNone = 0;
	constexpr DWORD BrokerShareRead = 1;
	constexpr DWORD BrokerShareWrite = 2;
	constexpr DWORD BrokerShareDelete = 4;
	constexpr DWORD BrokerCreateNew = 1;
	constexpr DWORD BrokerCreateAlways = 2;
	constexpr DWORD BrokerOpenExisting = 3;
	constexpr DWORD BrokerOpenAlways = 4;
	constexpr DWORD BrokerTruncateExisting = 5;

	bool WildcardMatch(const wchar_t* pattern, const wchar_t* value)
	{
		if (!pattern || !*pattern || (pattern[0] == L'*' && pattern[1] == 0)) return true;
		while (*pattern) {
			if (*pattern == L'*') {
				while (*pattern == L'*') ++pattern;
				if (!*pattern) return true;
				for (; *value; ++value) if (WildcardMatch(pattern, value)) return true;
				return false;
			}
			if (!*value || (*pattern != L'?' && towupper(*pattern) != towupper(*value))) return false;
			++pattern; ++value;
		}
		return *value == 0;
	}

	std::wstring NormalizeRelativePath(const wchar_t* path)
	{
		std::wstring relative = path ? path : L"";
		while (!relative.empty() && (relative.front() == L'\\' || relative.front() == L'/')) relative.erase(relative.begin());
		for (auto& character : relative) if (character == L'/') character = L'\\';
		return relative;
	}

	DWORD BrokerAccess(bool directory, std::uint32_t desiredAccess)
	{
		if (directory) return BrokerReadAttributes;
		const bool write = (desiredAccess & (GENERIC_WRITE | GENERIC_ALL | 0x00000116u)) != 0;
		return write ? BrokerWrite : BrokerRead;
	}

	DWORD BrokerSharing(std::uint32_t shareAccess)
	{
		DWORD sharing = BrokerShareNone;
		if (shareAccess & FILE_SHARE_READ) sharing |= BrokerShareRead;
		if (shareAccess & FILE_SHARE_WRITE) sharing |= BrokerShareWrite;
		if (shareAccess & FILE_SHARE_DELETE) sharing |= BrokerShareDelete;
		return sharing;
	}

	HRESULT __stdcall OpenBrokeredGameFile(const wchar_t* relativePath, bool directory,
		std::uint32_t desiredAccess, std::uint32_t shareAccess, std::uint32_t disposition,
		std::uint32_t, HANDLE* handle)
	{
		if (!handle) return E_POINTER;
		*handle = INVALID_HANDLE_VALUE;
		auto folder = UwpStorageBroker::GameFolder;
		if (!folder) return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
		const std::wstring relative = NormalizeRelativePath(relativePath);
		const auto access = BrokerAccess(directory, desiredAccess);
		const auto sharing = BrokerSharing(shareAccess);
		if (relative.empty()) {
			ComPtr<StorageItemHandleAccess> itemAccess;
			HRESULT result = reinterpret_cast<IInspectable*>(folder)->QueryInterface(IID_PPV_ARGS(&itemAccess));
			if (FAILED(result)) return result;
			return itemAccess->Create(access, sharing, BrokerOptionNone, nullptr, handle);
		}
		ComPtr<StorageFolderHandleAccess> folderAccess;
		HRESULT result = reinterpret_cast<IInspectable*>(folder)->QueryInterface(IID_PPV_ARGS(&folderAccess));
		if (FAILED(result)) return result;
		DWORD creation = BrokerOpenExisting;
		switch (disposition) {
		case 0: case 5: creation = BrokerCreateAlways; break;
		case 2: creation = BrokerCreateNew; break;
		case 3: creation = BrokerOpenAlways; break;
		case 4: creation = BrokerTruncateExisting; break;
		default: break;
		}
		return folderAccess->Create(relative.c_str(), creation, access, sharing, BrokerOptionNone, nullptr, handle);
	}

	HRESULT __stdcall EnumerateBrokeredGameDirectory(const wchar_t* relativePath,
		const wchar_t* mask, std::vector<WIN32_FIND_DATAW>* entries)
	{
		if (!entries) return E_POINTER;
		entries->clear();
		auto root = UwpStorageBroker::GameFolder;
		if (!root) return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
		try {
			auto folder = root;
			const std::wstring relative = NormalizeRelativePath(relativePath);
			if (!relative.empty()) {
				std::size_t begin = 0;
				while (begin < relative.size()) {
					const auto separator = relative.find(L'\\', begin);
					const std::wstring component = relative.substr(begin, separator - begin);
					if (!component.empty()) folder = create_task(folder->GetFolderAsync(ref new String(component.c_str()))).get();
					if (separator == std::wstring::npos) break;
					begin = separator + 1;
				}
			}
			const auto items = create_task(folder->GetItemsAsync()).get();
			for (auto item : items) {
				if (!WildcardMatch(mask, item->Name->Data())) continue;
				WIN32_FIND_DATAW data = {};
				wcsncpy_s(data.cFileName, item->Name->Data(), _TRUNCATE);
				data.dwFileAttributes = item->IsOfType(StorageItemTypes::Folder) ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
				const auto created = item->DateCreated.UniversalTime;
				data.ftCreationTime.dwLowDateTime = static_cast<DWORD>(created);
				data.ftCreationTime.dwHighDateTime = static_cast<DWORD>(created >> 32);
				if (item->IsOfType(StorageItemTypes::File)) {
					auto properties = create_task(safe_cast<StorageFile^>(item)->GetBasicPropertiesAsync()).get();
					data.nFileSizeLow = static_cast<DWORD>(properties->Size);
					data.nFileSizeHigh = static_cast<DWORD>(properties->Size >> 32);
					const auto modified = properties->DateModified.UniversalTime;
					data.ftLastWriteTime.dwLowDateTime = static_cast<DWORD>(modified);
					data.ftLastWriteTime.dwHighDateTime = static_cast<DWORD>(modified >> 32);
				}
				entries->push_back(data);
			}
			return S_OK;
		}
		catch (Exception^ error) {
			return error->HResult;
		}
	}
}

StorageFolder^ UwpStorageBroker::s_dataFolder = nullptr;
StorageFolder^ UwpStorageBroker::s_gameFolder = nullptr;
StorageFile^ UwpStorageBroker::s_gameFile = nullptr;
String^ UwpStorageBroker::s_gameRoot = nullptr;
String^ UwpStorageBroker::s_logPath = nullptr;

IAsyncAction^ UwpStorageBroker::InitializeAsync()
{
	CxbxUwpRegisterBrokeredFileAccess(&OpenBrokeredGameFile, &EnumerateBrokeredGameDirectory);
	if (s_dataFolder != nullptr) {
		return create_async([] {});
	}

	return create_async([]()
	{
		return create_task(ApplicationData::Current->LocalFolder->CreateFolderAsync("CxbxR", CreationCollisionOption::OpenIfExists))
			.then([](StorageFolder^ folder)
			{
				s_dataFolder = folder;
				s_logPath = folder->Path + "\\CxbxR.log";

				auto list = StorageApplicationPermissions::FutureAccessList;
				if (!list->ContainsItem("cxbxr-game-folder")) {
					return task_from_result<StorageFolder^>(nullptr);
				}
				return create_task(list->GetFolderAsync("cxbxr-game-folder"));
			})
			.then([](task<StorageFolder^> previous)
			{
				try {
					s_gameFolder = previous.get();
					s_gameRoot = s_gameFolder == nullptr ? nullptr : s_gameFolder->Path;
				}
				catch (Exception^) {
					// A removable location may no longer be available. Drop its stale
					// token and leave the app ready for a new picker selection.
					StorageApplicationPermissions::FutureAccessList->Remove("cxbxr-game-folder");
					s_gameFolder = nullptr;
					s_gameRoot = nullptr;
				}
			});
	});
}

IAsyncOperation<String^>^ UwpStorageBroker::SetGameFolderAsync(StorageFolder^ folder)
{
	return create_async([folder]()
	{
		if (folder == nullptr) {
			throw ref new InvalidArgumentException("A game folder is required.");
		}

		s_gameFolder = folder;
		s_gameRoot = folder->Path;
		// A FutureAccessList token survives suspension/restart. The StorageFolder
		// itself remains retained while emulation is active.
		auto list = StorageApplicationPermissions::FutureAccessList;
		if (list->ContainsItem("cxbxr-game-folder")) {
			list->Remove("cxbxr-game-folder");
		}
		list->Add(folder, "cxbxr-game-folder");
		return create_task(folder->GetFileAsync("default.xbe"))
			.then([](StorageFile^ file)
			{
				s_gameFile = file;
				auto access = StorageApplicationPermissions::FutureAccessList;
				if (access->ContainsItem("cxbxr-game-file")) access->Remove("cxbxr-game-file");
				access->Add(file, "cxbxr-game-file");
				return file->Path;
			});
	});
}

IAsyncOperation<String^>^ UwpStorageBroker::SetGameFileAsync(StorageFile^ file)
{
	return create_async([file]()
	{
		if (file == nullptr) {
			throw ref new InvalidArgumentException("A game file is required.");
		}
		s_gameFile = file;
		auto list = StorageApplicationPermissions::FutureAccessList;
		if (list->ContainsItem("cxbxr-game-file")) list->Remove("cxbxr-game-file");
		list->Add(file, "cxbxr-game-file");

		std::wstring path(file->Path->Data());
		const auto separator = path.find_last_of(L"\\/");
		s_gameRoot = ref new String((separator == std::wstring::npos ? path : path.substr(0, separator)).c_str());
		// Retain the parent too when the broker exposes it. If it does not, the XBE
		// itself remains usable; selecting the folder grants all sibling assets.
		return create_task(file->GetParentAsync()).then([file](task<StorageFolder^> parentTask)
		{
			try {
				auto parent = parentTask.get();
				if (parent != nullptr) {
					s_gameFolder = parent;
					s_gameRoot = parent->Path;
					auto access = StorageApplicationPermissions::FutureAccessList;
					if (access->ContainsItem("cxbxr-game-folder")) access->Remove("cxbxr-game-folder");
					access->Add(parent, "cxbxr-game-folder");
				}
			}
			catch (Exception^) {
				// FileOpenPicker still grants the selected StorageFile directly.
			}
			return file->Path;
		});
	});
}

IAsyncOperation<String^>^ UwpStorageBroker::ImportStreamAsync(IRandomAccessStream^ stream, String^ name)
{
	return create_async([stream, name]()
	{
		if (stream == nullptr || name == nullptr || name->IsEmpty()) {
			throw ref new InvalidArgumentException("A named random-access stream is required.");
		}
		if (s_dataFolder == nullptr) {
			throw ref new FailureException("InitializeAsync must complete before importing a stream.");
		}

		stream->Seek(0);
		return create_task(s_dataFolder->CreateFolderAsync("BrokeredFiles", CreationCollisionOption::OpenIfExists))
			.then([stream, name](StorageFolder^ destination)
			{
				return create_task(destination->CreateFileAsync(name, CreationCollisionOption::ReplaceExisting));
			})
			.then([stream](StorageFile^ destination)
			{
				return create_task(destination->OpenAsync(FileAccessMode::ReadWrite))
			.then([stream, destination](IRandomAccessStream^ output)
					{
						return create_task(RandomAccessStream::CopyAsync(stream, output))
							.then([destination](UINT64) { return destination->Path; });
					});
			});
	});
}

String^ UwpStorageBroker::DataRoot::get()
{
	return s_dataFolder == nullptr ? nullptr : s_dataFolder->Path;
}

String^ UwpStorageBroker::GameRoot::get()
{
	return s_gameRoot;
}

String^ UwpStorageBroker::LogPath::get()
{
	return s_logPath;
}

StorageFolder^ UwpStorageBroker::GameFolder::get()
{
	return s_gameFolder;
}
