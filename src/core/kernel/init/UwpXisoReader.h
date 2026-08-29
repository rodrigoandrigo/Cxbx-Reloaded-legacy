#pragma once

#include <Windows.h>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

struct CxbxUwpXisoEntry
{
	std::string name;
	std::string path;
	std::uint32_t startSector = 0;
	std::uint32_t size = 0;
	std::uint8_t attributes = 0;
	bool IsDirectory() const { return (attributes & 0x10) != 0; }
};

class CxbxUwpXisoReader final
{
public:
	CxbxUwpXisoReader() = default;
	~CxbxUwpXisoReader();
	CxbxUwpXisoReader(const CxbxUwpXisoReader&) = delete;
	CxbxUwpXisoReader& operator=(const CxbxUwpXisoReader&) = delete;

	HRESULT Mount(const wchar_t* path);
	bool IsMounted() const { return m_file != INVALID_HANDLE_VALUE; }
	HRESULT Find(const std::string& path, CxbxUwpXisoEntry& entry);
	HRESULT Enumerate(const std::string& path, std::vector<CxbxUwpXisoEntry>& entries);
	HRESULT Read(const CxbxUwpXisoEntry& entry, std::uint64_t offset, void* buffer,
		std::uint32_t length, std::uint32_t& transferred);
	HRESULT ReadImage(std::uint64_t offset, void* buffer, std::uint32_t length,
		std::uint32_t& transferred);
	HRESULT ReadAll(const std::string& path, std::vector<std::uint8_t>& bytes,
		std::uint64_t* imageOffset = nullptr);
	std::uint64_t ByteOffset(const CxbxUwpXisoEntry& entry) const;
	std::uint64_t ImageSize() const { return m_imageSize; }

private:
	HRESULT ReadAt(std::uint64_t offset, void* buffer, std::uint32_t length);
	HRESULT ReadDirectory(std::uint32_t sector, std::uint32_t size,
		const std::string& parent, std::vector<CxbxUwpXisoEntry>& entries);
	static std::string Normalize(const std::string& path);
	static bool EqualName(const std::string& left, const std::string& right);

	HANDLE m_file = INVALID_HANDLE_VALUE;
	std::uint64_t m_imageSize = 0;
	std::uint32_t m_fileSystemBaseSector = 0;
	std::uint32_t m_rootSector = 0;
	std::uint32_t m_rootSize = 0;
	mutable std::mutex m_mutex;
};
