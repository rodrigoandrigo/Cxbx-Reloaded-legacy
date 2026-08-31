#pragma once

#include <cstdint>
#include <string>

#include "emulator/CxbxEmbed.h"

// Thin C++ file layer over the C ABI. It keeps brokered objects out of the
// emulator and makes every read explicit and capability-scoped.
class CxbxBrokeredFile final
{
public:
	CxbxBrokeredFile(const CxbxEmbedBrokeredStorage& storage, CxbxEmbedStorageHandle handle, bool close_when_done = false);
	~CxbxBrokeredFile();

	CxbxBrokeredFile(const CxbxBrokeredFile&) = delete;
	CxbxBrokeredFile& operator=(const CxbxBrokeredFile&) = delete;

	bool GetSize(uint64_t& size, std::string& error) const;
	bool ReadAt(uint64_t offset, void* buffer, uint32_t requested, uint32_t& read, std::string& error) const;

private:
	const CxbxEmbedBrokeredStorage& m_storage;
	CxbxEmbedStorageHandle m_handle;
	bool m_closeWhenDone;
};

bool CxbxEmbedHasBrokeredTitle(const CxbxEmbedBrokeredStorage& storage);
bool CxbxEmbedMaterializeBrokeredTitle(const CxbxEmbedBrokeredStorage& storage,
	const std::string& cache_path, std::string& materialized_path, std::string& error);
