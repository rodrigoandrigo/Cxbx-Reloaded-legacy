#pragma once

#include <cstddef>
#include <cstdint>

using CxbxUwpDeviceLogger = void(*)(const char* text);

struct CxbxUwpGamepadState
{
	std::uint32_t packet;
	std::uint16_t buttons;
	std::uint8_t analog[8];
	std::int16_t leftX;
	std::int16_t leftY;
	std::int16_t rightX;
	std::int16_t rightY;
};

struct CxbxUwpDeviceSettings
{
	bool pcmCodec;
	bool xboxAdpcmCodec;
	bool unknownCodecs;
	bool networkEnabled;
	std::uint32_t consoleType;
};

// Host services deliberately use a plain C ABI.  The emulated devices never
// retain C++/CX objects and can therefore run on the lib86cpu worker thread.
using CxbxUwpAudioSubmit = void(*)(const std::int16_t* samples,
	std::uint32_t frameCount, std::uint32_t sampleRate, void* context);
using CxbxUwpEthernetTransmit = void(*)(const std::uint8_t* frame,
	std::uint32_t length, void* context);

void CxbxUwpSetGamepadState(std::uint32_t port, const CxbxUwpGamepadState* state);
void CxbxUwpSetDeviceSettings(const CxbxUwpDeviceSettings* settings);
void CxbxUwpSetAudioSubmitter(CxbxUwpAudioSubmit callback, void* context);
void CxbxUwpSetEthernetTransmitter(CxbxUwpEthernetTransmit callback, void* context);
bool CxbxUwpInjectEthernetFrame(const std::uint8_t* frame, std::uint32_t length);
std::uint32_t CxbxUwpReadHardwarePort(std::uint32_t port, std::uint32_t width);
void CxbxUwpWriteHardwarePort(std::uint32_t port, std::uint32_t value, std::uint32_t width);
bool CxbxUwpReadSmbusValue(std::uint8_t address, std::uint8_t command, bool word, std::uint32_t& value);
bool CxbxUwpWriteSmbusValue(std::uint8_t address, std::uint8_t command, bool word, std::uint32_t value);
std::uint32_t CxbxUwpReadPciConfig(std::uint32_t bus, std::uint32_t slotFunction, std::uint32_t reg, std::uint32_t width);
void CxbxUwpWritePciConfig(std::uint32_t bus, std::uint32_t slotFunction, std::uint32_t reg, std::uint32_t value, std::uint32_t width);

class CxbxUwpDeviceBus final
{
public:
	struct Impl;
	static constexpr std::uint32_t MmioBase = 0xFE800000u;
	static constexpr std::uint32_t MmioSize = 0x00700400u;
	static constexpr std::uint32_t McpxBase = 0xFFFFFE00u;
	static constexpr std::uint32_t McpxSize = 0x200u;

	CxbxUwpDeviceBus(std::uint8_t* ram, std::size_t ramSize,
		const wchar_t* dataRoot, CxbxUwpDeviceLogger logger);
	~CxbxUwpDeviceBus();
	CxbxUwpDeviceBus(const CxbxUwpDeviceBus&) = delete;
	CxbxUwpDeviceBus& operator=(const CxbxUwpDeviceBus&) = delete;

	std::uint8_t ReadMmio8(std::uint32_t address);
	std::uint16_t ReadMmio16(std::uint32_t address);
	std::uint32_t ReadMmio32(std::uint32_t address);
	std::uint64_t ReadMmio64(std::uint32_t address);
	void WriteMmio8(std::uint32_t address, std::uint8_t value);
	void WriteMmio16(std::uint32_t address, std::uint16_t value);
	void WriteMmio32(std::uint32_t address, std::uint32_t value);
	void WriteMmio64(std::uint32_t address, std::uint64_t value);

	std::uint8_t ReadPort8(std::uint32_t port);
	std::uint16_t ReadPort16(std::uint32_t port);
	std::uint32_t ReadPort32(std::uint32_t port);
	void WritePort8(std::uint32_t port, std::uint8_t value);
	void WritePort16(std::uint32_t port, std::uint16_t value);
	void WritePort32(std::uint32_t port, std::uint32_t value);

	// Advances asynchronous DMA engines, USB frames, APU voices and timers.
	// Called at every lib86cpu timeslice and is safe to call more frequently.
	void Tick();

private:
	Impl* m_impl;
};
