#include "UwpDeviceBus.h"
#include "UwpDeviceInterrupts.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace
{
	constexpr std::uint32_t ApuBase = 0xFE800000u;
	constexpr std::uint32_t ApuSize = 0x00080000u;
	constexpr std::uint32_t Ac97Base = 0xFEC00000u;
	constexpr std::uint32_t Ac97Size = 0x00001000u;
	constexpr std::uint32_t UsbBase = 0xFED00000u;
	constexpr std::uint32_t UsbSize = 0x00001000u;
	constexpr std::uint32_t NvnetBase = 0xFEF00000u;
	constexpr std::uint32_t NvnetSize = 0x00000400u;
	constexpr std::uint32_t PciAddressPort = 0xCF8u;
	constexpr std::uint32_t PciDataPort = 0xCFCu;
	constexpr std::uint32_t SmbusBase = 0xC000u;
	constexpr std::uint32_t ApuPortBase = 0xD000u;
	constexpr std::uint32_t NvnetPortBase = 0xE000u;

	constexpr std::uint32_t NvIrqStatus = 0x000;
	constexpr std::uint32_t NvIrqMask = 0x004;
	constexpr std::uint32_t NvMacA = 0x0A8;
	constexpr std::uint32_t NvMacB = 0x0AC;
	constexpr std::uint32_t NvTxRing = 0x100;
	constexpr std::uint32_t NvRxRing = 0x104;
	constexpr std::uint32_t NvRingSizes = 0x108;
	constexpr std::uint32_t NvLinkSpeed = 0x110;
	constexpr std::uint32_t NvTxRxControl = 0x144;
	constexpr std::uint32_t NvMiiStatus = 0x180;
	constexpr std::uint32_t NvMiiControl = 0x190;
	constexpr std::uint32_t NvMiiData = 0x194;
	constexpr std::uint16_t NvTxValid = 0x8000;
	constexpr std::uint16_t NvRxAvail = 0x8000;

	constexpr std::uint32_t OhciControl = 0x04;
	constexpr std::uint32_t OhciCommand = 0x08;
	constexpr std::uint32_t OhciInterruptStatus = 0x0C;
	constexpr std::uint32_t OhciInterruptEnable = 0x10;
	constexpr std::uint32_t OhciInterruptDisable = 0x14;
	constexpr std::uint32_t OhciHcca = 0x18;
	constexpr std::uint32_t OhciControlHead = 0x20;
	constexpr std::uint32_t OhciBulkHead = 0x28;
	constexpr std::uint32_t OhciDoneHead = 0x30;
	constexpr std::uint32_t OhciFrameInterval = 0x34;
	constexpr std::uint32_t OhciFrameRemaining = 0x38;
	constexpr std::uint32_t OhciFrameNumber = 0x3C;
	constexpr std::uint32_t OhciRhDescriptorA = 0x48;
	constexpr std::uint32_t OhciRhDescriptorB = 0x4C;
	constexpr std::uint32_t OhciRhStatus = 0x50;
	constexpr std::uint32_t OhciRhPort0 = 0x54;
	constexpr std::uint32_t OhciWdh = 1u << 1;
	constexpr std::uint32_t OhciRhsc = 1u << 6;
	constexpr std::uint32_t OhciMie = 1u << 31;

	struct HostState
	{
		std::mutex mutex;
		std::array<CxbxUwpGamepadState, 4> pads = {};
		CxbxUwpDeviceSettings settings = { true, true, true, true, 0 };
		CxbxUwpAudioSubmit audio = nullptr;
		void* audioContext = nullptr;
		CxbxUwpEthernetTransmit ethernet = nullptr;
		void* ethernetContext = nullptr;
		// Device I/O is executed synchronously by the guest CPU.  Keeping the
		// active bus behind the same mutex used by UI gamepad/audio settings can
		// deadlock HalReadWritePCISpace while the UI or an audio callback is being
		// torn down.  The bus lifetime is session-wide, so an atomic publication is
		// sufficient and keeps PCI/PMIO out of the host callback lock domain.
		std::atomic<void*> active{ nullptr };
	};

	HostState& Hosts()
	{
		static HostState state;
		return state;
	}

	template<typename T>
	T Load(const std::uint8_t* bytes, std::size_t size, std::uint32_t offset, T fallback = {})
	{
		T value = fallback;
		if (bytes && offset <= size && sizeof(T) <= size - offset) std::memcpy(&value, bytes + offset, sizeof(T));
		return value;
	}

	template<typename T>
	void Store(std::uint8_t* bytes, std::size_t size, std::uint32_t offset, T value)
	{
		if (bytes && offset <= size && sizeof(T) <= size - offset) std::memcpy(bytes + offset, &value, sizeof(T));
	}

	std::uint16_t ClampAxis(double value)
	{
		return static_cast<std::uint16_t>((std::max)(0.0, (std::min)(65535.0, value)));
	}
}

struct CxbxUwpDeviceBus::Impl
{
	std::uint8_t* ram;
	std::size_t ramSize;
	CxbxUwpDeviceLogger logger;
	std::wstring dataRoot;
	std::uint32_t pciAddress = 0;
	std::unordered_map<std::uint32_t, std::uint32_t> pciConfigWrites;
	std::array<std::uint8_t, ApuSize> apu = {};
	std::array<std::uint8_t, Ac97Size> ac97 = {};
	std::array<std::uint8_t, UsbSize> ohci = {};
	std::array<std::uint8_t, NvnetSize> nvnet = {};
	std::array<std::uint8_t, CxbxUwpDeviceBus::McpxSize> mcpx = {};
	std::array<std::uint8_t, 256> eeprom = {};
	std::array<std::uint8_t, 256> smc = {};
	std::array<std::uint8_t, 32> smbBlock = {};
	std::uint8_t smbStatus = 0;
	std::uint8_t smbControl = 0;
	std::uint8_t smbAddress = 0;
	std::uint8_t smbCommand = 0;
	std::uint8_t smbData0 = 0;
	std::uint8_t smbData1 = 0;
	std::uint8_t smbIndex = 0;
	std::uint8_t picVersionIndex = 0;
	std::uint8_t xidAddress = 0;
	std::array<std::uint8_t, 8> setupPacket = {};
	std::uint32_t setupLength = 0;
	std::uint32_t txIndex = 0;
	std::uint32_t rxIndex = 0;
	std::deque<std::vector<std::uint8_t>> receivedFrames;
	std::mutex networkMutex;
	std::chrono::steady_clock::time_point lastTick = std::chrono::steady_clock::now();
	std::uint64_t audioCursor = 0;
	bool eepromDirty = false;

	Impl(std::uint8_t* guestRam, std::size_t guestRamSize, const wchar_t* root, CxbxUwpDeviceLogger log)
		: ram(guestRam), ramSize(guestRamSize), logger(log), dataRoot(root ? root : L"")
	{
		Reset();
		LoadEeprom();
	}

	~Impl()
	{
		SaveEeprom();
	}

	void Log(const char* value) const { if (logger) logger(value); }

	void Reset()
	{
		apu.fill(0); ac97.fill(0); ohci.fill(0); nvnet.fill(0); mcpx.fill(0);
		pciAddress = 0; pciConfigWrites.clear();
		Store<std::uint32_t>(ohci.data(), ohci.size(), 0x00, 0x10u);
		Store<std::uint32_t>(ohci.data(), ohci.size(), OhciFrameInterval, 0x2EDF2EDFu);
		Store<std::uint32_t>(ohci.data(), ohci.size(), OhciRhDescriptorA, 0x02000204u);
		Store<std::uint32_t>(ohci.data(), ohci.size(), OhciRhDescriptorB, 0x00000000u);
		for (unsigned port = 0; port < 4; ++port) {
			Store<std::uint32_t>(ohci.data(), ohci.size(), OhciRhPort0 + port * 4, 0x00010101u);
		}
		Store<std::uint32_t>(nvnet.data(), nvnet.size(), NvMacA, 0x12005452u);
		Store<std::uint32_t>(nvnet.data(), nvnet.size(), NvMacB, 0x00000100u);
		Store<std::uint32_t>(nvnet.data(), nvnet.size(), NvLinkSpeed, 100000u);
		Store<std::uint32_t>(nvnet.data(), nvnet.size(), NvTxRxControl, 8u);
		smc.fill(0);
		smc[0x03] = 0x60; // tray closed, media present
		smc[0x04] = 1;    // HDTV AV pack as used by the retail legacy profile
		smc[0x06] = 20; smc[0x08] = 0x0F; smc[0x09] = 45; smc[0x0A] = 40;
		smbStatus = smbControl = smbAddress = smbCommand = smbData0 = smbData1 = smbIndex = 0;
	}

	std::wstring EepromPath() const
	{
		if (dataRoot.empty()) return {};
		return dataRoot + (dataRoot.back() == L'\\' ? L"" : L"\\") + L"EEPROM.bin";
	}

	void LoadEeprom()
	{
		// Deterministic retail EEPROM defaults; mutable fields are persisted in LocalState.
		for (std::size_t i = 0; i < eeprom.size(); ++i) eeprom[i] = static_cast<std::uint8_t>((i * 73u + 0x31u) & 0xFFu);
		const auto path = EepromPath();
		if (path.empty()) return;
		CREATEFILE2_EXTENDED_PARAMETERS parameters = { sizeof(parameters) };
		parameters.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
		HANDLE file = CreateFile2FromAppW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, &parameters);
		if (file == INVALID_HANDLE_VALUE) return;
		DWORD read = 0; ReadFile(file, eeprom.data(), static_cast<DWORD>(eeprom.size()), &read, nullptr); CloseHandle(file);
	}

	void SaveEeprom()
	{
		if (!eepromDirty) return;
		const auto path = EepromPath();
		if (path.empty()) return;
		CREATEFILE2_EXTENDED_PARAMETERS parameters = { sizeof(parameters) };
		parameters.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
		HANDLE file = CreateFile2FromAppW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS, &parameters);
		if (file == INVALID_HANDLE_VALUE) return;
		DWORD written = 0; WriteFile(file, eeprom.data(), static_cast<DWORD>(eeprom.size()), &written, nullptr); CloseHandle(file);
		eepromDirty = written != eeprom.size();
	}

	std::uint32_t PciConfig() const
	{
		if ((pciAddress & 0x80000000u) == 0) return 0xFFFFFFFFu;
		const std::uint8_t bus = static_cast<std::uint8_t>(pciAddress >> 16);
		const std::uint8_t slot = static_cast<std::uint8_t>((pciAddress >> 11) & 31);
		const std::uint8_t function = static_cast<std::uint8_t>((pciAddress >> 8) & 7);
		const std::uint8_t reg = static_cast<std::uint8_t>(pciAddress & 0xFC);
		std::uint32_t device = 0xFFFFFFFFu, bar0 = 0, bar1 = 0, bar2 = 0, classCode = 0;
		if (bus == 0 && slot == 1 && function == 1) { device = 0x01B410DEu; bar1 = SmbusBase | 1; classCode = 0x0C0500u; }
		else if (bus == 0 && slot == 2 && function == 0) { device = 0x01C210DEu; bar0 = UsbBase; classCode = 0x0C0310u; }
		else if (bus == 0 && slot == 4 && function == 0) { device = 0x01C310DEu; bar0 = NvnetBase; bar1 = NvnetPortBase | 1; classCode = 0x020000u; }
		else if (bus == 0 && slot == 5 && function == 0) { device = 0x01B010DEu; bar0 = ApuPortBase | 1; bar1 = 0xD200u | 1; bar2 = ApuBase; classCode = 0x040100u; }
		else if (bus == 0 && slot == 6 && function == 0) { device = 0x01B110DEu; bar0 = Ac97Base; classCode = 0x040100u; }
		else if (bus == 1 && slot == 0 && function == 0) { device = 0x02A510DEu; bar0 = 0xFD000000u; bar1 = 0xF0000000u; classCode = 0x030000u; }
		if (device == 0xFFFFFFFFu) return device;
		const std::uint32_t key = pciAddress & 0x00FFFFFCu;
		const auto configured = pciConfigWrites.find(key);
		if (configured != pciConfigWrites.end()) return configured->second;
		switch (reg) {
		case 0x00: return device;
		case 0x04: return 0x00000007u;
		case 0x08: return (classCode << 8) | 0xA1u;
		case 0x0C: return 0;
		case 0x10: return bar0;
		case 0x14: return bar1;
		case 0x18: return bar2;
		case 0x3C: return bus == 1 ? 3u : (slot == 2 ? 1u : slot == 4 ? 4u : slot == 5 ? 5u : slot == 6 ? 6u : 11u);
		default: return 0;
		}
	}

	void WritePciConfig(std::uint32_t value, std::uint32_t width, std::uint32_t byteOffset)
	{
		if ((pciAddress & 0x80000000u) == 0 || !width || width > 4 || byteOffset + width > 4) return;
		const std::uint32_t alignedRegister = pciAddress & 0xFCu;
		// Vendor/device and class/revision are read-only. Command/status, BARs,
		// interrupt routing and the NV2A AGP command block are programmable.
		if (alignedRegister == 0x00u || alignedRegister == 0x08u) return;
		std::uint32_t current = PciConfig();
		const std::uint32_t bits = width == 4 ? 0xFFFFFFFFu : ((1u << (width * 8u)) - 1u);
		const std::uint32_t shift = byteOffset * 8u;
		current = (current & ~(bits << shift)) | ((value & bits) << shift);
		pciConfigWrites[pciAddress & 0x00FFFFFCu] = current;
	}

	std::uint8_t SmcRead(std::uint8_t command)
	{
		if (command == 1) {
			const char version[] = "P01";
			const auto value = static_cast<std::uint8_t>(version[picVersionIndex++ % 3]);
			return value;
		}
		if (command >= 0x1C && command <= 0x1F) return 0;
		return smc[command];
	}

	void SmcWrite(std::uint8_t command, std::uint8_t value)
	{
		if (command == 1 && value == 0) picVersionIndex = 0;
		if (command == 0x0C) smc[0x03] = value ? 0x60 : 0x10;
		if (command == 0x0E) smc[0x0F] = value;
		smc[command] = value;
	}

	void ExecuteSmbus()
	{
		const bool read = (smbAddress & 1) != 0;
		const std::uint8_t device = static_cast<std::uint8_t>((smbAddress >> 1) & 0x7F);
		const std::uint8_t protocol = smbControl & 7;
		smbStatus = 0;
		auto readByte = [&](std::uint8_t command) -> std::uint8_t {
			if (device == 0x10) return SmcRead(command);
			if (device == 0x54) return eeprom[command];
			if (device == 0x4C) return command == 0 ? 40 : command == 1 ? 45 : 0;
			return 0xFF;
		};
		auto writeByte = [&](std::uint8_t command, std::uint8_t value) {
			if (device == 0x10) SmcWrite(command, value);
			else if (device == 0x54) { eeprom[command] = value; eepromDirty = true; }
		};
		if (device != 0x10 && device != 0x54 && device != 0x4C) smbStatus = 1u << 2;
		else if (protocol == 1 || protocol == 2) {
			if (read) smbData0 = readByte(smbCommand); else writeByte(smbCommand, smbData0);
		}
		else if (protocol == 3) {
			if (read) { smbData0 = readByte(smbCommand); smbData1 = readByte(static_cast<std::uint8_t>(smbCommand + 1)); }
			else { writeByte(smbCommand, smbData0); writeByte(static_cast<std::uint8_t>(smbCommand + 1), smbData1); }
		}
		else if (protocol == 5) {
			const std::uint8_t count = (std::min<std::uint8_t>)(smbData0, 32);
			if (read) { for (std::uint8_t i = 0; i < count; ++i) smbBlock[i] = readByte(static_cast<std::uint8_t>(smbCommand + i)); }
			else { for (std::uint8_t i = 0; i < count; ++i) writeByte(static_cast<std::uint8_t>(smbCommand + i), smbBlock[i]); }
		}
		smbStatus |= 1u << 4;
		if ((smbControl & (1u << 4)) && (smbStatus & 0x35)) CxbxUwpPulseDeviceInterrupt(11);
	}

	std::uint8_t ReadSmbus(std::uint32_t port)
	{
		switch ((port - SmbusBase) & 0x1F) {
		case 0: return smbStatus;
		case 2: return smbControl & 0x1F;
		case 4: return smbAddress;
		case 6: return smbData0;
		case 7: return smbData1;
		case 8: return smbCommand;
		case 9: { const auto value = smbBlock[smbIndex++ & 31]; return value; }
		default: return 0;
		}
	}

	void WriteSmbus(std::uint32_t port, std::uint8_t value)
	{
		switch ((port - SmbusBase) & 0x1F) {
		case 0: smbStatus &= ~value; if (!(smbStatus & 0x35)) CxbxUwpAcknowledgeDeviceInterrupt(11, 0xFFFFFFFFu); break;
		case 2: smbControl = value; if (value & 0x20) smbStatus |= 1; if (value & 8) ExecuteSmbus(); break;
		case 4: smbAddress = value; break;
		case 6: smbData0 = value; break;
		case 7: smbData1 = value; break;
		case 8: smbCommand = value; break;
		case 9: smbBlock[smbIndex++ & 31] = value; break;
		}
	}

	bool RamRange(std::uint32_t address, std::size_t size) const
	{
		return address <= ramSize && size <= ramSize - address;
	}

	void UpdateOhciIrq()
	{
		const auto status = Load<std::uint32_t>(ohci.data(), ohci.size(), OhciInterruptStatus);
		const auto enable = Load<std::uint32_t>(ohci.data(), ohci.size(), OhciInterruptEnable);
		if ((enable & OhciMie) && (status & enable & ~OhciMie)) CxbxUwpAssertDeviceInterrupt(CxbxUwpDeviceIrq::Usb0, status & enable);
		else CxbxUwpAcknowledgeDeviceInterrupt(CxbxUwpDeviceIrq::Usb0, 0xFFFFFFFFu);
	}

	void CompleteTd(std::uint32_t edAddress, std::uint32_t tdAddress, std::uint32_t nextTd)
	{
		std::uint32_t head = Load<std::uint32_t>(ram, ramSize, edAddress + 8);
		Store<std::uint32_t>(ram, ramSize, edAddress + 8, (head & 3u) | (nextTd & ~0xFu));
		std::uint32_t flags = Load<std::uint32_t>(ram, ramSize, tdAddress);
		flags &= 0x0FFFFFFFu;
		Store<std::uint32_t>(ram, ramSize, tdAddress, flags);
		const auto oldDone = Load<std::uint32_t>(ohci.data(), ohci.size(), OhciDoneHead);
		Store<std::uint32_t>(ram, ramSize, tdAddress + 8, oldDone);
		Store<std::uint32_t>(ohci.data(), ohci.size(), OhciDoneHead, tdAddress);
		auto irq = Load<std::uint32_t>(ohci.data(), ohci.size(), OhciInterruptStatus);
		Store<std::uint32_t>(ohci.data(), ohci.size(), OhciInterruptStatus, irq | OhciWdh);
	}

	std::vector<std::uint8_t> ControlResponse() const
	{
		if (setupLength < 8) return {};
		const std::uint8_t request = setupPacket[1];
		const std::uint16_t value = static_cast<std::uint16_t>(setupPacket[2] | (setupPacket[3] << 8));
		if (request == 6 && (value >> 8) == 1) return { 18,1,0x10,1,0,0,0,8,0x5E,0x04,0x02,0x02,0x01,0x01,1,2,0,1 };
		if (request == 6 && (value >> 8) == 2) return {
			32,2,32,0,1,1,0,0x80,50,
			9,4,0,0,2,0x58,0x42,0,0,
			7,5,0x82,3,32,0,4,
			7,5,0x02,3,32,0,4 };
		if (request == 6 && (value >> 8) == 3) {
			if ((value & 0xFF) == 0) return { 4,3,9,4 };
			const char* text = (value & 0xFF) == 1 ? "Microsoft" : "Controller S";
			std::vector<std::uint8_t> result(2 + std::strlen(text) * 2); result[0] = static_cast<std::uint8_t>(result.size()); result[1] = 3;
			for (std::size_t i = 0; text[i]; ++i) result[2 + i * 2] = static_cast<std::uint8_t>(text[i]); return result;
		}
		if (request == 8) return { 1 };
		return {};
	}

	std::array<std::uint8_t, 20> XidReport(std::uint32_t port) const
	{
		CxbxUwpGamepadState pad = {};
		{ auto& hosts = Hosts(); std::lock_guard<std::mutex> lock(hosts.mutex); pad = hosts.pads[(std::min)(port, 3u)]; }
		std::array<std::uint8_t, 20> report = {};
		report[0] = 0; report[1] = 20; std::memcpy(report.data() + 2, &pad.buttons, 2);
		std::memcpy(report.data() + 4, pad.analog, 8);
		std::memcpy(report.data() + 12, &pad.leftX, 2); std::memcpy(report.data() + 14, &pad.leftY, 2);
		std::memcpy(report.data() + 16, &pad.rightX, 2); std::memcpy(report.data() + 18, &pad.rightY, 2);
		return report;
	}

	bool ServiceTd(std::uint32_t edAddress)
	{
		if (!RamRange(edAddress, 16)) return false;
		const std::uint32_t edFlags = Load<std::uint32_t>(ram, ramSize, edAddress);
		const std::uint32_t head = Load<std::uint32_t>(ram, ramSize, edAddress + 8) & ~0xFu;
		const std::uint32_t tail = Load<std::uint32_t>(ram, ramSize, edAddress + 4) & ~0xFu;
		if (!head || head == tail || !RamRange(head, 16)) return false;
		const std::uint32_t tdFlags = Load<std::uint32_t>(ram, ramSize, head);
		const std::uint32_t cbp = Load<std::uint32_t>(ram, ramSize, head + 4);
		const std::uint32_t next = Load<std::uint32_t>(ram, ramSize, head + 8) & ~0xFu;
		const std::uint32_t end = Load<std::uint32_t>(ram, ramSize, head + 12);
		const std::uint32_t direction = (tdFlags >> 19) & 3;
		const std::uint32_t endpoint = (edFlags >> 7) & 0xF;
		const std::uint32_t deviceAddress = edFlags & 0x7Fu;
		std::size_t length = cbp && end >= cbp ? static_cast<std::size_t>(end - cbp + 1) : 0;
		length = (std::min<std::size_t>)(length, 4096);
		if (direction == 0 && length >= 8 && RamRange(cbp, 8)) { std::memcpy(setupPacket.data(), ram + cbp, 8); setupLength = 8; }
		else if (direction == 2 && length && RamRange(cbp, length)) {
			if (endpoint == 0) {
				auto response = ControlResponse(); const auto count = (std::min)(length, response.size());
				if (count) std::memcpy(ram + cbp, response.data(), count);
			}
			else { auto report = XidReport(deviceAddress > 0 ? deviceAddress - 1 : 0); const auto count = (std::min)(length, report.size()); std::memcpy(ram + cbp, report.data(), count); }
		}
		if (direction == 1 && endpoint == 0 && setupLength >= 8 && setupPacket[1] == 5) xidAddress = setupPacket[2];
		Store<std::uint32_t>(ram, ramSize, head + 4, 0u);
		CompleteTd(edAddress, head, next);
		return true;
	}

	void ServiceEdList(std::uint32_t first)
	{
		std::uint32_t ed = first & ~0xFu;
		for (unsigned guard = 0; ed && guard < 128; ++guard) {
			ServiceTd(ed);
			if (!RamRange(ed, 16)) break;
			ed = Load<std::uint32_t>(ram, ramSize, ed + 12) & ~0xFu;
		}
	}

	void TickOhci()
	{
		auto frame = static_cast<std::uint16_t>(Load<std::uint32_t>(ohci.data(), ohci.size(), OhciFrameNumber) + 1);
		Store<std::uint32_t>(ohci.data(), ohci.size(), OhciFrameNumber, frame);
		const auto hcca = Load<std::uint32_t>(ohci.data(), ohci.size(), OhciHcca) & ~0xFFu;
		if (RamRange(hcca, 256)) {
			Store<std::uint16_t>(ram, ramSize, hcca + 0x80, frame);
			const auto periodic = Load<std::uint32_t>(ram, ramSize, hcca + (frame & 31) * 4);
			ServiceEdList(periodic);
		}
		const auto control = Load<std::uint32_t>(ohci.data(), ohci.size(), OhciControl);
		const auto command = Load<std::uint32_t>(ohci.data(), ohci.size(), OhciCommand);
		if ((control & (1u << 4)) && (command & 2)) ServiceEdList(Load<std::uint32_t>(ohci.data(), ohci.size(), OhciControlHead));
		if ((control & (1u << 5)) && (command & 4)) ServiceEdList(Load<std::uint32_t>(ohci.data(), ohci.size(), OhciBulkHead));
		if (hcca) { const auto done = Load<std::uint32_t>(ohci.data(), ohci.size(), OhciDoneHead); if (done) { Store<std::uint32_t>(ram, ramSize, hcca + 0x84, done); Store<std::uint32_t>(ohci.data(), ohci.size(), OhciDoneHead, 0u); } }
		UpdateOhciIrq();
	}

	void UpdateNvnetIrq()
	{
		const auto status = Load<std::uint32_t>(nvnet.data(), nvnet.size(), NvIrqStatus);
		const auto mask = Load<std::uint32_t>(nvnet.data(), nvnet.size(), NvIrqMask);
		if (status & mask) CxbxUwpAssertDeviceInterrupt(CxbxUwpDeviceIrq::Network, status & mask);
		else CxbxUwpAcknowledgeDeviceInterrupt(CxbxUwpDeviceIrq::Network, 0xFFFFFFFFu);
	}

	void ReceiveFrame(const std::uint8_t* data, std::size_t length)
	{
		if (!data || length < 14 || length > 2048) return;
		std::lock_guard<std::mutex> lock(networkMutex);
		receivedFrames.emplace_back(data, data + length);
		while (receivedFrames.size() > 32) receivedFrames.pop_front();
	}

	void ProcessNvnet()
	{
		{ auto& hosts = Hosts(); std::lock_guard<std::mutex> hostLock(hosts.mutex); if (!hosts.settings.networkEnabled) return; }
		const std::uint32_t ringSizes = Load<std::uint32_t>(nvnet.data(), nvnet.size(), NvRingSizes);
		const std::uint32_t txCount = (ringSizes & 0xFFFFu) + 1;
		const std::uint32_t rxCount = (ringSizes >> 16) + 1;
		const std::uint32_t txBase = Load<std::uint32_t>(nvnet.data(), nvnet.size(), NvTxRing);
		for (unsigned guard = 0; guard < (std::min)(txCount, 256u); ++guard) {
			const std::uint32_t desc = txBase + (txIndex % txCount) * 8;
			if (!RamRange(desc, 8)) break;
			const auto buffer = Load<std::uint32_t>(ram, ramSize, desc);
			auto length = Load<std::uint16_t>(ram, ramSize, desc + 4);
			auto flags = Load<std::uint16_t>(ram, ramSize, desc + 6);
			if (!(flags & NvTxValid)) break;
			length = static_cast<std::uint16_t>((std::min<std::uint32_t>)(length + 1, 2048));
			if (RamRange(buffer, length)) {
				CxbxUwpEthernetTransmit callback = nullptr; void* context = nullptr;
				{ auto& hosts = Hosts(); std::lock_guard<std::mutex> lock(hosts.mutex); callback = hosts.ethernet; context = hosts.ethernetContext; }
				if (callback) callback(ram + buffer, length, context);
				else ReceiveFrame(ram + buffer, length); // deterministic isolated virtual cable
			}
			flags &= ~NvTxValid; Store<std::uint16_t>(ram, ramSize, desc + 4, static_cast<std::uint16_t>(length + 4)); Store<std::uint16_t>(ram, ramSize, desc + 6, flags);
			++txIndex;
			auto irq = Load<std::uint32_t>(nvnet.data(), nvnet.size(), NvIrqStatus); Store<std::uint32_t>(nvnet.data(), nvnet.size(), NvIrqStatus, irq | 0x10u);
		}
		std::lock_guard<std::mutex> lock(networkMutex);
		while (!receivedFrames.empty()) {
			const std::uint32_t rxBase = Load<std::uint32_t>(nvnet.data(), nvnet.size(), NvRxRing);
			const std::uint32_t desc = rxBase + (rxIndex % rxCount) * 8;
			if (!RamRange(desc, 8)) break;
			const auto buffer = Load<std::uint32_t>(ram, ramSize, desc);
			const auto capacity = Load<std::uint16_t>(ram, ramSize, desc + 4);
			const auto flags = Load<std::uint16_t>(ram, ramSize, desc + 6);
			if (!(flags & NvRxAvail)) break;
			auto& frame = receivedFrames.front(); const auto length = (std::min<std::size_t>)(capacity, frame.size());
			if (!RamRange(buffer, length)) break;
			std::memcpy(ram + buffer, frame.data(), length); Store<std::uint16_t>(ram, ramSize, desc + 4, static_cast<std::uint16_t>(length)); Store<std::uint16_t>(ram, ramSize, desc + 6, 0x11u);
			receivedFrames.pop_front(); ++rxIndex;
			auto irq = Load<std::uint32_t>(nvnet.data(), nvnet.size(), NvIrqStatus); Store<std::uint32_t>(nvnet.data(), nvnet.size(), NvIrqStatus, irq | 0x02u);
		}
		UpdateNvnetIrq();
	}

	void TickAudio()
	{
		// MCPX APU scatter/gather output contract.  The guest supplies a ring base,
		// byte length, cursor and control at the AC97 bus-master window.  This also
		// gives HLE titles a common native sink without desktop DirectSound.
		const auto control = Load<std::uint32_t>(ac97.data(), ac97.size(), 0x00);
		const auto address = Load<std::uint32_t>(ac97.data(), ac97.size(), 0x04);
		const auto bytes = Load<std::uint32_t>(ac97.data(), ac97.size(), 0x08);
		const auto rate = Load<std::uint32_t>(ac97.data(), ac97.size(), 0x10, 48000u);
		if (!(control & 1) || bytes < 4 || bytes > 1u << 20 || !RamRange(address, bytes)) return;
		CxbxUwpAudioSubmit callback = nullptr; void* context = nullptr;
		{ auto& hosts = Hosts(); std::lock_guard<std::mutex> lock(hosts.mutex); if (!hosts.settings.pcmCodec) return; callback = hosts.audio; context = hosts.audioContext; }
		if (!callback) return;
		const std::uint32_t frames = (std::min<std::uint32_t>)(256, bytes / 4);
		const std::uint32_t offset = static_cast<std::uint32_t>(audioCursor % bytes);
		if (offset + frames * 4 <= bytes) callback(reinterpret_cast<const std::int16_t*>(ram + address + offset), frames, rate ? rate : 48000, context);
		else {
			std::array<std::int16_t, 512> samples = {}; for (std::uint32_t i = 0; i < frames * 2; ++i) samples[i] = Load<std::int16_t>(ram, ramSize, address + ((offset + i * 2) % bytes));
			callback(samples.data(), frames, rate ? rate : 48000, context);
		}
		audioCursor = (audioCursor + frames * 4) % bytes; Store<std::uint32_t>(ac97.data(), ac97.size(), 0x0C, static_cast<std::uint32_t>(audioCursor));
		CxbxUwpPulseDeviceInterrupt(CxbxUwpDeviceIrq::AudioCodec);
	}

	std::uint8_t ReadMmioByte(std::uint32_t address)
	{
		if (address >= ApuBase && address < ApuBase + ApuSize) {
			const auto offset = address - ApuBase; if (offset >= 0x20000 && offset < 0x30000 && (offset & 0xFFFF) == 0x10) return 0x80;
			if (offset >= 0x200C && offset < 0x2010) { const auto ticks = static_cast<std::uint32_t>(GetTickCount64() * 48); return reinterpret_cast<const std::uint8_t*>(&ticks)[offset - 0x200C]; }
			return apu[offset];
		}
		if (address >= Ac97Base && address < Ac97Base + Ac97Size) return ac97[address - Ac97Base];
		if (address >= UsbBase && address < UsbBase + UsbSize) {
			const auto offset = address - UsbBase; if (offset >= OhciFrameRemaining && offset < OhciFrameRemaining + 4) { const std::uint32_t remaining = 0x2EDF; return reinterpret_cast<const std::uint8_t*>(&remaining)[offset - OhciFrameRemaining]; }
			return ohci[offset];
		}
		if (address >= NvnetBase && address < NvnetBase + NvnetSize) {
			const auto offset = address - NvnetBase;
			if (offset >= NvMiiData && offset < NvMiiData + 4) { const std::uint32_t phy = 0x01E1u; return reinterpret_cast<const std::uint8_t*>(&phy)[offset - NvMiiData]; }
			if (offset >= NvMiiStatus && offset < NvMiiStatus + 4) return 0;
			return nvnet[offset];
		}
		if (address >= CxbxUwpDeviceBus::McpxBase && address < CxbxUwpDeviceBus::McpxBase + CxbxUwpDeviceBus::McpxSize) return mcpx[address - CxbxUwpDeviceBus::McpxBase];
		return 0xFF;
	}

	void WriteMmioByte(std::uint32_t address, std::uint8_t value)
	{
		if (address >= ApuBase && address < ApuBase + ApuSize) { apu[address - ApuBase] = value; return; }
		if (address >= Ac97Base && address < Ac97Base + Ac97Size) { ac97[address - Ac97Base] = value; return; }
		if (address >= UsbBase && address < UsbBase + UsbSize) { ohci[address - UsbBase] = value; return; }
		if (address >= NvnetBase && address < NvnetBase + NvnetSize) { nvnet[address - NvnetBase] = value; return; }
		if (address >= CxbxUwpDeviceBus::McpxBase && address < CxbxUwpDeviceBus::McpxBase + CxbxUwpDeviceBus::McpxSize) mcpx[address - CxbxUwpDeviceBus::McpxBase] = value;
	}

	std::uint32_t ReadMmio(std::uint32_t address, unsigned size)
	{
		std::uint32_t result = 0; for (unsigned i = 0; i < size; ++i) result |= static_cast<std::uint32_t>(ReadMmioByte(address + i)) << (i * 8); return result;
	}

	void WriteMmio(std::uint32_t address, std::uint32_t value, unsigned size)
	{
		if (address >= UsbBase && address < UsbBase + UsbSize && size == 4) {
			const auto offset = address - UsbBase;
			if (offset == OhciInterruptStatus) { const auto old = Load<std::uint32_t>(ohci.data(), ohci.size(), offset); Store<std::uint32_t>(ohci.data(), ohci.size(), offset, old & ~value); UpdateOhciIrq(); return; }
			if (offset == OhciInterruptEnable) { const auto old = Load<std::uint32_t>(ohci.data(), ohci.size(), offset); Store<std::uint32_t>(ohci.data(), ohci.size(), offset, old | value); UpdateOhciIrq(); return; }
			if (offset == OhciInterruptDisable) { const auto old = Load<std::uint32_t>(ohci.data(), ohci.size(), OhciInterruptEnable); Store<std::uint32_t>(ohci.data(), ohci.size(), OhciInterruptEnable, old & ~value); UpdateOhciIrq(); return; }
			if (offset >= OhciRhPort0 && offset < OhciRhPort0 + 16) { auto status = Load<std::uint32_t>(ohci.data(), ohci.size(), offset); status &= ~(value & 0x001F0000u); if (value & (1u << 4)) status |= 0x00100103u; if (value & (1u << 8)) status |= 0x00000100u; Store<std::uint32_t>(ohci.data(), ohci.size(), offset, status); return; }
		}
		if (address >= NvnetBase && address < NvnetBase + NvnetSize && size == 4) {
			const auto offset = address - NvnetBase;
			if (offset == NvIrqStatus) { auto old = Load<std::uint32_t>(nvnet.data(), nvnet.size(), offset); Store<std::uint32_t>(nvnet.data(), nvnet.size(), offset, old & ~value); UpdateNvnetIrq(); return; }
			if (offset == NvTxRxControl && (value & 1)) { Store<std::uint32_t>(nvnet.data(), nvnet.size(), offset, value); ProcessNvnet(); return; }
		}
		for (unsigned i = 0; i < size; ++i) WriteMmioByte(address + i, static_cast<std::uint8_t>(value >> (i * 8)));
		if (address == NvnetBase + NvIrqMask) UpdateNvnetIrq();
	}

	void Tick()
	{
		const auto now = std::chrono::steady_clock::now();
		if (now - lastTick < std::chrono::microseconds(750)) return;
		lastTick = now;
		TickOhci(); ProcessNvnet(); TickAudio();
		const auto apuNotify = Load<std::uint32_t>(apu.data(), apu.size(), 0x1000); const auto apuEnable = Load<std::uint32_t>(apu.data(), apu.size(), 0x1004);
		if (apuNotify & apuEnable) CxbxUwpAssertDeviceInterrupt(CxbxUwpDeviceIrq::Apu, apuNotify & apuEnable);
	}
};

void CxbxUwpSetGamepadState(std::uint32_t port, const CxbxUwpGamepadState* state)
{
	if (port >= 4) return; auto& hosts = Hosts(); std::lock_guard<std::mutex> lock(hosts.mutex); if (state) hosts.pads[port] = *state; else hosts.pads[port] = {};
}

void CxbxUwpSetDeviceSettings(const CxbxUwpDeviceSettings* settings)
{
	if (!settings) return;
	auto& hosts = Hosts(); std::lock_guard<std::mutex> lock(hosts.mutex); hosts.settings = *settings;
}

void CxbxUwpSetAudioSubmitter(CxbxUwpAudioSubmit callback, void* context)
{
	auto& hosts = Hosts(); std::lock_guard<std::mutex> lock(hosts.mutex); hosts.audio = callback; hosts.audioContext = context;
}

void CxbxUwpSetEthernetTransmitter(CxbxUwpEthernetTransmit callback, void* context)
{
	auto& hosts = Hosts(); std::lock_guard<std::mutex> lock(hosts.mutex); hosts.ethernet = callback; hosts.ethernetContext = context;
}

bool CxbxUwpInjectEthernetFrame(const std::uint8_t* frame, std::uint32_t length)
{
	auto* impl = static_cast<CxbxUwpDeviceBus::Impl*>(Hosts().active.load(std::memory_order_acquire));
	if (!impl || !frame || length < 14 || length > 2048) return false;
	impl->ReceiveFrame(frame, length); return true;
}

std::uint32_t CxbxUwpReadHardwarePort(std::uint32_t port, std::uint32_t width)
{
	auto* impl = static_cast<CxbxUwpDeviceBus::Impl*>(Hosts().active.load(std::memory_order_acquire)); if (!impl) return 0xFFFFFFFFu;
	if (port >= PciDataPort && width >= 1 && width <= 4 && port + width <= PciDataPort + 4) {
		const std::uint32_t value = impl->PciConfig() >> ((port - PciDataPort) * 8u);
		return width == 1 ? value & 0xFFu : width == 2 ? value & 0xFFFFu : value;
	}
	auto readByte = [impl](std::uint32_t p) -> std::uint8_t { return p >= SmbusBase && p < SmbusBase + 32 ? impl->ReadSmbus(p) : p >= ApuPortBase && p < ApuPortBase + 0x280 ? impl->apu[(p - ApuPortBase) & (ApuSize - 1)] : p >= NvnetPortBase && p < NvnetPortBase + 8 ? impl->nvnet[p - NvnetPortBase] : 0xFF; };
	if (width == 1) return readByte(port);
	if (width == 2) return readByte(port) | (static_cast<std::uint32_t>(readByte(port + 1)) << 8);
	if (port == PciAddressPort) return impl->pciAddress; if (port == PciDataPort) return impl->PciConfig();
	return readByte(port) | (static_cast<std::uint32_t>(readByte(port + 1)) << 8) | (static_cast<std::uint32_t>(readByte(port + 2)) << 16) | (static_cast<std::uint32_t>(readByte(port + 3)) << 24);
}

void CxbxUwpWriteHardwarePort(std::uint32_t port, std::uint32_t value, std::uint32_t width)
{
	auto* impl = static_cast<CxbxUwpDeviceBus::Impl*>(Hosts().active.load(std::memory_order_acquire)); if (!impl) return;
	if (port == PciAddressPort && width == 4) { impl->pciAddress = value; return; }
	if (port >= PciDataPort && width >= 1 && width <= 4 && port + width <= PciDataPort + 4) {
		impl->WritePciConfig(value, width, port - PciDataPort); return;
	}
	for (std::uint32_t index = 0; index < width; ++index) {
		const auto p = port + index;
		const auto byte = static_cast<std::uint8_t>(value >> (index * 8));
		if (p >= SmbusBase && p < SmbusBase + 32) impl->WriteSmbus(p, byte);
		else if (p >= ApuPortBase && p < ApuPortBase + 0x280) impl->apu[(p - ApuPortBase) & (ApuSize - 1)] = byte;
	}
}

bool CxbxUwpReadSmbusValue(std::uint8_t address, std::uint8_t command, bool word, std::uint32_t& value)
{
	auto* impl = static_cast<CxbxUwpDeviceBus::Impl*>(Hosts().active.load(std::memory_order_acquire)); if (!impl) return false;
	impl->smbAddress = address | 1; impl->smbCommand = command; impl->smbControl = static_cast<std::uint8_t>((word ? 3 : 2) | 8); impl->ExecuteSmbus();
	value = impl->smbData0 | (word ? static_cast<std::uint32_t>(impl->smbData1) << 8 : 0); return (impl->smbStatus & 4) == 0;
}

bool CxbxUwpWriteSmbusValue(std::uint8_t address, std::uint8_t command, bool word, std::uint32_t value)
{
	auto* impl = static_cast<CxbxUwpDeviceBus::Impl*>(Hosts().active.load(std::memory_order_acquire)); if (!impl) return false;
	impl->smbAddress = address & 0xFE; impl->smbCommand = command; impl->smbData0 = static_cast<std::uint8_t>(value); impl->smbData1 = static_cast<std::uint8_t>(value >> 8); impl->smbControl = static_cast<std::uint8_t>((word ? 3 : 2) | 8); impl->ExecuteSmbus(); return (impl->smbStatus & 4) == 0;
}

std::uint32_t CxbxUwpReadPciConfig(std::uint32_t bus, std::uint32_t slotFunction, std::uint32_t reg, std::uint32_t width)
{
	auto* impl = static_cast<CxbxUwpDeviceBus::Impl*>(Hosts().active.load(std::memory_order_acquire)); if (!impl) return 0xFFFFFFFFu;
	// PCI_SLOT_NUMBER stores DeviceNumber in bits 0..4 and FunctionNumber in
	// bits 5..7. PCI type-1 configuration addresses use those fields at bits
	// 11..15 and 8..10 respectively; shifting the packed byte by eight swaps
	// their interpretation for every non-zero slot.
	const std::uint32_t device = slotFunction & 0x1Fu;
	const std::uint32_t function = (slotFunction >> 5) & 7u;
	impl->pciAddress = 0x80000000u | ((bus & 0xFFu) << 16) |
		(device << 11) | (function << 8) | (reg & 0xFCu);
	const auto value = impl->PciConfig() >> ((reg & 3u) * 8);
	return width == 1 ? value & 0xFFu : width == 2 ? value & 0xFFFFu : value;
}

void CxbxUwpWritePciConfig(std::uint32_t bus, std::uint32_t slotFunction,
	std::uint32_t reg, std::uint32_t value, std::uint32_t width)
{
	auto* impl = static_cast<CxbxUwpDeviceBus::Impl*>(Hosts().active.load(std::memory_order_acquire)); if (!impl) return;
	const std::uint32_t device = slotFunction & 0x1Fu;
	const std::uint32_t function = (slotFunction >> 5) & 7u;
	impl->pciAddress = 0x80000000u | ((bus & 0xFFu) << 16) |
		(device << 11) | (function << 8) | (reg & 0xFCu);
	impl->WritePciConfig(value, width, reg & 3u);
}

CxbxUwpDeviceBus::CxbxUwpDeviceBus(std::uint8_t* ram, std::size_t ramSize, const wchar_t* dataRoot, CxbxUwpDeviceLogger logger)
	: m_impl(new Impl(ram, ramSize, dataRoot, logger))
{
	Hosts().active.store(m_impl, std::memory_order_release);
	if (logger) logger("[uwp-devices] PCI/SMBus/SMC/EEPROM/MCPX, OHCI/XID, APU/AC97 e NVNet inicializados.\r\n");
}

CxbxUwpDeviceBus::~CxbxUwpDeviceBus()
{
	void* expected = m_impl;
	Hosts().active.compare_exchange_strong(expected, nullptr, std::memory_order_acq_rel);
	delete m_impl;
}

std::uint8_t CxbxUwpDeviceBus::ReadMmio8(std::uint32_t a) { return m_impl->ReadMmioByte(a); }
std::uint16_t CxbxUwpDeviceBus::ReadMmio16(std::uint32_t a) { return static_cast<std::uint16_t>(m_impl->ReadMmio(a, 2)); }
std::uint32_t CxbxUwpDeviceBus::ReadMmio32(std::uint32_t a) { return m_impl->ReadMmio(a, 4); }
std::uint64_t CxbxUwpDeviceBus::ReadMmio64(std::uint32_t a) { return static_cast<std::uint64_t>(m_impl->ReadMmio(a, 4)) | (static_cast<std::uint64_t>(m_impl->ReadMmio(a + 4, 4)) << 32); }
void CxbxUwpDeviceBus::WriteMmio8(std::uint32_t a, std::uint8_t v) { m_impl->WriteMmio(a, v, 1); }
void CxbxUwpDeviceBus::WriteMmio16(std::uint32_t a, std::uint16_t v) { m_impl->WriteMmio(a, v, 2); }
void CxbxUwpDeviceBus::WriteMmio32(std::uint32_t a, std::uint32_t v) { m_impl->WriteMmio(a, v, 4); }
void CxbxUwpDeviceBus::WriteMmio64(std::uint32_t a, std::uint64_t v) { m_impl->WriteMmio(a, static_cast<std::uint32_t>(v), 4); m_impl->WriteMmio(a + 4, static_cast<std::uint32_t>(v >> 32), 4); }

std::uint8_t CxbxUwpDeviceBus::ReadPort8(std::uint32_t port)
{
	if (port >= SmbusBase && port < SmbusBase + 32) return m_impl->ReadSmbus(port);
	if (port >= PciDataPort && port < PciDataPort + 4) return static_cast<std::uint8_t>(m_impl->PciConfig() >> ((port - PciDataPort) * 8));
	if (port >= ApuPortBase && port < ApuPortBase + 0x280) return m_impl->apu[(port - ApuPortBase) & (ApuSize - 1)];
	if (port >= NvnetPortBase && port < NvnetPortBase + 8) return m_impl->nvnet[port - NvnetPortBase];
	return 0xFF;
}
std::uint16_t CxbxUwpDeviceBus::ReadPort16(std::uint32_t p) { return static_cast<std::uint16_t>(ReadPort8(p) | (ReadPort8(p + 1) << 8)); }
std::uint32_t CxbxUwpDeviceBus::ReadPort32(std::uint32_t p) { if (p == PciAddressPort) return m_impl->pciAddress; if (p == PciDataPort) return m_impl->PciConfig(); return ReadPort16(p) | (static_cast<std::uint32_t>(ReadPort16(p + 2)) << 16); }
void CxbxUwpDeviceBus::WritePort8(std::uint32_t port, std::uint8_t value)
{
	if (port >= PciDataPort && port < PciDataPort + 4) m_impl->WritePciConfig(value, 1, port - PciDataPort);
	else if (port >= SmbusBase && port < SmbusBase + 32) m_impl->WriteSmbus(port, value);
	else if (port >= ApuPortBase && port < ApuPortBase + 0x280) m_impl->apu[(port - ApuPortBase) & (ApuSize - 1)] = value;
	else if (port >= NvnetPortBase && port < NvnetPortBase + 8) m_impl->nvnet[port - NvnetPortBase] = value;
}
void CxbxUwpDeviceBus::WritePort16(std::uint32_t p, std::uint16_t v) { if (p >= PciDataPort && p + 1 < PciDataPort + 4) { m_impl->WritePciConfig(v, 2, p - PciDataPort); return; } WritePort8(p, static_cast<std::uint8_t>(v)); WritePort8(p + 1, static_cast<std::uint8_t>(v >> 8)); }
void CxbxUwpDeviceBus::WritePort32(std::uint32_t p, std::uint32_t v) { if (p == PciAddressPort) { m_impl->pciAddress = v; return; } if (p == PciDataPort) { m_impl->WritePciConfig(v, 4, 0); return; } WritePort16(p, static_cast<std::uint16_t>(v)); WritePort16(p + 2, static_cast<std::uint16_t>(v >> 16)); }
void CxbxUwpDeviceBus::Tick() { m_impl->Tick(); }
