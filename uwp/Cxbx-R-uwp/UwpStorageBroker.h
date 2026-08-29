#pragma once

#include <ppltasks.h>

namespace Cxbx_R_uwp
{
	// Owns the UWP capability boundary. Games remain at their original picked
	// location; only writable emulator data and logs live in LocalFolder.
	public ref class UwpStorageBroker sealed
	{
	public:
		static Windows::Foundation::IAsyncAction^ InitializeAsync();
		static Windows::Foundation::IAsyncOperation<Platform::String^>^ SetGameFolderAsync(Windows::Storage::StorageFolder^ folder);
		static Windows::Foundation::IAsyncOperation<Platform::String^>^ SetGameFileAsync(Windows::Storage::StorageFile^ file);
		static Windows::Foundation::IAsyncOperation<Platform::String^>^ ImportStreamAsync(Windows::Storage::Streams::IRandomAccessStream^ stream, Platform::String^ name);

		static property Platform::String^ DataRoot { Platform::String^ get(); }
		static property Platform::String^ GameRoot { Platform::String^ get(); }
		static property Platform::String^ LogPath { Platform::String^ get(); }

	internal:
		// Retained StorageFolder used only by the native handle bridge. Keeping it
		// internal prevents a WinRT ABI from exposing implementation-only types.
		static property Windows::Storage::StorageFolder^ GameFolder { Windows::Storage::StorageFolder^ get(); }

	private:
		static Windows::Storage::StorageFolder^ s_dataFolder;
		static Windows::Storage::StorageFolder^ s_gameFolder;
		static Windows::Storage::StorageFile^ s_gameFile;
		static Platform::String^ s_gameRoot;
		static Platform::String^ s_logPath;
	};
}
