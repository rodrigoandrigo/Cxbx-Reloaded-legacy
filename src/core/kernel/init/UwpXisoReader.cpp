#include "UwpXisoReader.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>

namespace
{
	constexpr std::uint32_t SectorSize = 2048;
	constexpr char Signature[] = "MICROSOFT*XBOX*MEDIA";
	constexpr std::size_t SignatureLength = sizeof(Signature) - 1;
	constexpr std::uint32_t VolumeDescriptorSector = 32;
	constexpr std::uint8_t DirectoryAttribute = 0x10;

	std::uint16_t Read16(const std::uint8_t* bytes) { std::uint16_t value = 0; std::memcpy(&value, bytes, sizeof(value)); return value; }
	std::uint32_t Read32(const std::uint8_t* bytes) { std::uint32_t value = 0; std::memcpy(&value, bytes, sizeof(value)); return value; }
}

CxbxUwpXisoReader::~CxbxUwpXisoReader()
{
	if (m_file != INVALID_HANDLE_VALUE) CloseHandle(m_file);
}

HRESULT CxbxUwpXisoReader::ReadAt(std::uint64_t offset, void* buffer, std::uint32_t length)
{
	if (m_file == INVALID_HANDLE_VALUE || !buffer || offset > m_imageSize || length > m_imageSize - offset) return HRESULT_FROM_WIN32(ERROR_HANDLE_EOF);
	std::lock_guard<std::mutex> lock(m_mutex); LARGE_INTEGER position = {}; position.QuadPart = offset;
	if (!SetFilePointerEx(m_file, position, nullptr, FILE_BEGIN)) return HRESULT_FROM_WIN32(GetLastError());
	std::uint8_t* output = static_cast<std::uint8_t*>(buffer); std::uint32_t done = 0;
	while (done < length) { DWORD read = 0; const DWORD chunk = (std::min)(length - done, 1u << 20); if (!ReadFile(m_file, output + done, chunk, &read, nullptr) || !read) return HRESULT_FROM_WIN32(GetLastError() ? GetLastError() : ERROR_HANDLE_EOF); done += read; }
	return S_OK;
}

HRESULT CxbxUwpXisoReader::Mount(const wchar_t* path)
{
	if (!path || !*path) return E_INVALIDARG; if (m_file != INVALID_HANDLE_VALUE) { CloseHandle(m_file); m_file = INVALID_HANDLE_VALUE; }
	CREATEFILE2_EXTENDED_PARAMETERS parameters = { sizeof(parameters) }; parameters.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
	m_file = CreateFile2FromAppW(path, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, &parameters);
	if (m_file == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError()); LARGE_INTEGER size = {};
	if (!GetFileSizeEx(m_file, &size) || size.QuadPart < 64ll * SectorSize) return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT); m_imageSize = size.QuadPart;
	std::array<std::uint8_t, SectorSize> descriptor = {}; const std::uint64_t sectors = m_imageSize / SectorSize;
	const std::uint32_t candidates[] = { 0, 0x30600 };
	auto testBase = [&](std::uint32_t base) { if (static_cast<std::uint64_t>(base) + VolumeDescriptorSector >= sectors) return false; if (FAILED(ReadAt((static_cast<std::uint64_t>(base) + VolumeDescriptorSector) * SectorSize, descriptor.data(), SectorSize))) return false; return std::memcmp(descriptor.data(), Signature, SignatureLength) == 0 && std::memcmp(descriptor.data() + SectorSize - SignatureLength, Signature, SignatureLength) == 0; };
	bool mounted = false; for (const auto candidate : candidates) if (testBase(candidate)) { m_fileSystemBaseSector = candidate; mounted = true; break; }
	if (!mounted) { const std::uint64_t scanLimit = (std::min<std::uint64_t>)(sectors, 0x40000); for (std::uint32_t descriptorSector = VolumeDescriptorSector; descriptorSector < scanLimit; ++descriptorSector) { if (FAILED(ReadAt(static_cast<std::uint64_t>(descriptorSector) * SectorSize, descriptor.data(), SectorSize))) break; if (std::memcmp(descriptor.data(), Signature, SignatureLength) == 0 && std::memcmp(descriptor.data() + SectorSize - SignatureLength, Signature, SignatureLength) == 0) { m_fileSystemBaseSector = descriptorSector - VolumeDescriptorSector; mounted = true; break; } } }
	if (!mounted) { CloseHandle(m_file); m_file = INVALID_HANDLE_VALUE; return HRESULT_FROM_WIN32(ERROR_UNRECOGNIZED_VOLUME); }
	m_rootSector = Read32(descriptor.data() + 20); m_rootSize = Read32(descriptor.data() + 24);
	if (!m_rootSize || ByteOffset({ {}, {}, m_rootSector, m_rootSize, DirectoryAttribute }) + m_rootSize > m_imageSize) { CloseHandle(m_file); m_file = INVALID_HANDLE_VALUE; return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT); }
	return S_OK;
}

std::string CxbxUwpXisoReader::Normalize(const std::string& value)
{
	std::string result; for (char character : value) { if (character == '/') character = '\\'; if (character == '\\') { if (!result.empty() && result.back() != '\\') result.push_back(character); } else result.push_back(character); }
	while (!result.empty() && result.front() == '\\') result.erase(result.begin()); while (!result.empty() && result.back() == '\\') result.pop_back(); return result;
}

bool CxbxUwpXisoReader::EqualName(const std::string& left, const std::string& right)
{
	return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin(), [](char a, char b) { return std::toupper(static_cast<unsigned char>(a)) == std::toupper(static_cast<unsigned char>(b)); });
}

std::uint64_t CxbxUwpXisoReader::ByteOffset(const CxbxUwpXisoEntry& entry) const
{
	return (static_cast<std::uint64_t>(m_fileSystemBaseSector) + entry.startSector) * SectorSize;
}

HRESULT CxbxUwpXisoReader::ReadDirectory(std::uint32_t sector, std::uint32_t size, const std::string& parent, std::vector<CxbxUwpXisoEntry>& entries)
{
	if (!size || size > 64u * 1024 * 1024) return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT); std::vector<std::uint8_t> bytes(size);
	CxbxUwpXisoEntry directory = { {}, parent, sector, size, DirectoryAttribute }; std::uint32_t transferred = 0; HRESULT result = Read(directory, 0, bytes.data(), size, transferred); if (FAILED(result) || transferred != size) return FAILED(result) ? result : HRESULT_FROM_WIN32(ERROR_HANDLE_EOF);
	entries.clear(); std::uint32_t position = 0;
	while (position + 14 <= size) { const auto* item = bytes.data() + position; const std::uint32_t start = Read32(item + 4); if (!start || start == 0xFFFFFFFFu) { position = (position + SectorSize) & ~(SectorSize - 1); continue; } const std::uint32_t fileSize = Read32(item + 8); const std::uint8_t attributes = item[12], nameLength = item[13]; if (!nameLength || position + 14u + nameLength > size || (static_cast<std::uint64_t>(m_fileSystemBaseSector) + start) * SectorSize + fileSize > m_imageSize) { position = (position + SectorSize) & ~(SectorSize - 1); continue; } std::string name(reinterpret_cast<const char*>(item + 14), nameLength); std::string path = parent.empty() ? name : parent + "\\" + name; entries.push_back({ name, path, start, fileSize, attributes }); position = (position + 14u + nameLength + 3u) & ~3u; }
	return S_OK;
}

HRESULT CxbxUwpXisoReader::Enumerate(const std::string& path, std::vector<CxbxUwpXisoEntry>& entries)
{
	CxbxUwpXisoEntry directory; const std::string normalized = Normalize(path); if (normalized.empty()) directory = { {}, {}, m_rootSector, m_rootSize, DirectoryAttribute }; else { HRESULT result = Find(normalized, directory); if (FAILED(result)) return result; if (!directory.IsDirectory()) return HRESULT_FROM_WIN32(ERROR_DIRECTORY); }
	return ReadDirectory(directory.startSector, directory.size, directory.path, entries);
}

HRESULT CxbxUwpXisoReader::Find(const std::string& path, CxbxUwpXisoEntry& entry)
{
	const std::string normalized = Normalize(path); if (normalized.empty()) { entry = { {}, {}, m_rootSector, m_rootSize, DirectoryAttribute }; return S_OK; }
	CxbxUwpXisoEntry directory = { {}, {}, m_rootSector, m_rootSize, DirectoryAttribute }; std::size_t cursor = 0;
	while (cursor < normalized.size()) { const auto separator = normalized.find('\\', cursor); const std::string component = normalized.substr(cursor, separator == std::string::npos ? std::string::npos : separator - cursor); std::vector<CxbxUwpXisoEntry> entries; HRESULT result = ReadDirectory(directory.startSector, directory.size, directory.path, entries); if (FAILED(result)) return result; auto found = std::find_if(entries.begin(), entries.end(), [&](const auto& candidate) { return EqualName(candidate.name, component); }); if (found == entries.end()) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND); directory = *found; if (separator == std::string::npos) { entry = directory; return S_OK; } if (!directory.IsDirectory()) return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND); cursor = separator + 1; }
	return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
}

HRESULT CxbxUwpXisoReader::Read(const CxbxUwpXisoEntry& entry, std::uint64_t offset, void* buffer, std::uint32_t length, std::uint32_t& transferred)
{
	transferred = 0; if (offset >= entry.size) return S_OK; const std::uint32_t available = entry.size - static_cast<std::uint32_t>(offset); transferred = (std::min)(length, available); return transferred ? ReadAt(ByteOffset(entry) + offset, buffer, transferred) : S_OK;
}

HRESULT CxbxUwpXisoReader::ReadImage(std::uint64_t offset, void* buffer,
	std::uint32_t length, std::uint32_t& transferred)
{
	transferred = 0;
	if (!buffer && length) return E_POINTER;
	if (offset >= m_imageSize) return S_OK;
	transferred = static_cast<std::uint32_t>((std::min<std::uint64_t>)(length, m_imageSize - offset));
	return transferred ? ReadAt(offset, buffer, transferred) : S_OK;
}

HRESULT CxbxUwpXisoReader::ReadAll(const std::string& path, std::vector<std::uint8_t>& bytes, std::uint64_t* imageOffset)
{
	CxbxUwpXisoEntry entry; HRESULT result = Find(path, entry); if (FAILED(result)) return result; if (entry.IsDirectory()) return HRESULT_FROM_WIN32(ERROR_DIRECTORY); bytes.resize(entry.size); std::uint32_t transferred = 0; result = Read(entry, 0, bytes.data(), entry.size, transferred); if (SUCCEEDED(result) && transferred != entry.size) result = HRESULT_FROM_WIN32(ERROR_HANDLE_EOF); if (SUCCEEDED(result) && imageOffset) *imageOffset = ByteOffset(entry); return result;
}
