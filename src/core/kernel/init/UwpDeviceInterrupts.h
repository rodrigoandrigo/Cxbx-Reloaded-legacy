#pragma once

#include <cstdint>

// Physical Xbox PCI interrupt lines used by UWP device producers.
enum class CxbxUwpDeviceIrq : std::uint32_t
{
	Usb0 = 1,
	Gpu = 3,
	Network = 4,
	Apu = 5,
	AudioCodec = 6,
	Usb1 = 9,
	Ide = 14,
};

// Thread-safe producer ABI. Pulse models an edge/completion; Assert and
// Acknowledge model individual bits behind a level-sensitive interrupt line.
void CxbxUwpPulseDeviceInterrupt(std::uint32_t busInterruptLevel);
void CxbxUwpAssertDeviceInterrupt(std::uint32_t busInterruptLevel, std::uint32_t sourceMask);
void CxbxUwpAcknowledgeDeviceInterrupt(std::uint32_t busInterruptLevel, std::uint32_t sourceMask);
inline void CxbxUwpPulseDeviceInterrupt(CxbxUwpDeviceIrq irq) { CxbxUwpPulseDeviceInterrupt(static_cast<std::uint32_t>(irq)); }
inline void CxbxUwpAssertDeviceInterrupt(CxbxUwpDeviceIrq irq, std::uint32_t sourceMask) { CxbxUwpAssertDeviceInterrupt(static_cast<std::uint32_t>(irq), sourceMask); }
inline void CxbxUwpAcknowledgeDeviceInterrupt(CxbxUwpDeviceIrq irq, std::uint32_t sourceMask) { CxbxUwpAcknowledgeDeviceInterrupt(static_cast<std::uint32_t>(irq), sourceMask); }
