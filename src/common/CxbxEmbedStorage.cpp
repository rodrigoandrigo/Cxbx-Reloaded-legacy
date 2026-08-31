#include "CxbxEmbedStorage.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <limits>
#include <vector>

namespace {
constexpr uint32_t kCopyChunkSize = 1024u * 1024u;

const char* StorageResultText(CxbxEmbedStorageResult result)
{
	switch (result) {
	case CXBX_EMBED_STORAGE_ACCESS_DENIED: return "access denied";
	case CXBX_EMBED_STORAGE_NOT_FOUND: return "not found";
	case CXBX_EMBED_STORAGE_INVALID_HANDLE: return "invalid storage handle";
	case CXBX_EMBED_STORAGE_NOT_SUPPORTED: return "not supported";
	case CXBX_EMBED_STORAGE_IO_ERROR: return "I/O error";
	default: return "unknown storage error";
	}
}
}

CxbxBrokeredFile::CxbxBrokeredFile(const CxbxEmbedBrokeredStorage& storage,
	CxbxEmbedStorageHandle handle, bool close_when_done)
	: m_storage(storage), m_handle(handle), m_closeWhenDone(close_when_done)
{
}

CxbxBrokeredFile::~CxbxBrokeredFile()
{
	if (m_closeWhenDone && m_handle != CXBX_EMBED_INVALID_STORAGE_HANDLE && m_storage.close) {
		m_storage.close(m_storage.user_data, m_handle);
	}
}

bool CxbxBrokeredFile::GetSize(uint64_t& size, std::string& error) const
{
	if (!m_storage.get_size) {
		error = "The brokered storage host did not provide get_size.";
		return false;
	}
	const auto result = m_storage.get_size(m_storage.user_data, m_handle, &size);
	if (result != CXBX_EMBED_STORAGE_OK) {
		error = std::string("Could not query brokered file size: ") + StorageResultText(result) + ".";
		return false;
	}
	return true;
}

bool CxbxBrokeredFile::ReadAt(uint64_t offset, void* buffer, uint32_t requested,
	uint32_t& read, std::string& error) const
{
	read = 0;
	if (!m_storage.read_at) {
		error = "The brokered storage host did not provide read_at.";
		return false;
	}
	const auto result = m_storage.read_at(m_storage.user_data, m_handle, offset, buffer, requested, &read);
	if (result != CXBX_EMBED_STORAGE_OK) {
		error = std::string("Could not read brokered file: ") + StorageResultText(result) + ".";
		return false;
	}
	if (read > requested) {
		error = "The brokered storage host returned more bytes than requested.";
		return false;
	}
	return true;
}

bool CxbxEmbedHasBrokeredTitle(const CxbxEmbedBrokeredStorage& storage)
{
	if (storage.struct_size < sizeof(CxbxEmbedBrokeredStorage) ||
		storage.abi_version != CXBX_EMBED_STORAGE_VERSION || !storage.get_size || !storage.read_at) {
		return false;
	}
	return storage.title_file != CXBX_EMBED_INVALID_STORAGE_HANDLE ||
		(storage.content_folder != CXBX_EMBED_INVALID_STORAGE_HANDLE &&
			storage.title_relative_path_utf8 && storage.title_relative_path_utf8[0] != '\0' &&
			storage.open_relative && storage.close);
}

bool CxbxEmbedMaterializeBrokeredTitle(const CxbxEmbedBrokeredStorage& storage,
	const std::string& cache_path, std::string& materialized_path, std::string& error)
{
	if (!CxbxEmbedHasBrokeredTitle(storage)) {
		error = "No valid brokered title file was provided.";
		return false;
	}
	if (cache_path.empty()) {
		error = "A LocalFolder-derived cache path is required for a brokered title.";
		return false;
	}

	CxbxEmbedStorageHandle source_handle = storage.title_file;
	bool close_source = false;
	if (source_handle == CXBX_EMBED_INVALID_STORAGE_HANDLE) {
		const auto result = storage.open_relative(storage.user_data, storage.content_folder,
			storage.title_relative_path_utf8, CXBX_EMBED_STORAGE_READ, &source_handle);
		if (result != CXBX_EMBED_STORAGE_OK) {
			error = std::string("Could not open the brokered title from its folder: ") + StorageResultText(result) + ".";
			return false;
		}
		if (source_handle == CXBX_EMBED_INVALID_STORAGE_HANDLE) {
			error = "The brokered storage host returned an invalid title handle.";
			return false;
		}
		close_source = true;
	}

	CxbxBrokeredFile source(storage, source_handle, close_source);
	uint64_t size = 0;
	if (!source.GetSize(size, error)) {
		return false;
	}
	if (size > static_cast<uint64_t>((std::numeric_limits<size_t>::max)())) {
		error = "The brokered title is too large for this process.";
		return false;
	}

	std::error_code ec;
	const auto staging_directory = std::filesystem::path(cache_path) / "BrokeredTitles";
	std::filesystem::create_directories(staging_directory, ec);
	if (ec) {
		error = "Could not create the LocalFolder cache directory: " + ec.message();
		return false;
	}
	const auto staging_file = staging_directory / "title.xbe";
	std::ofstream destination(staging_file, std::ios::binary | std::ios::trunc);
	if (!destination.is_open()) {
		error = "Could not create the staged title in the LocalFolder cache.";
		return false;
	}

	std::vector<uint8_t> buffer(kCopyChunkSize);
	for (uint64_t offset = 0; offset < size;) {
		const auto remaining = size - offset;
		const auto requested = static_cast<uint32_t>((std::min)(remaining, static_cast<uint64_t>(buffer.size())));
		uint32_t read = 0;
		if (!source.ReadAt(offset, buffer.data(), requested, read, error) || read == 0) {
			if (error.empty()) {
				error = "The brokered title stream ended before its declared size.";
			}
			return false;
		}
		destination.write(reinterpret_cast<const char*>(buffer.data()), read);
		if (!destination.good()) {
			error = "Could not write the staged title into the LocalFolder cache.";
			return false;
		}
		offset += read;
	}
	destination.close();
	materialized_path = staging_file.string();
	return true;
}
