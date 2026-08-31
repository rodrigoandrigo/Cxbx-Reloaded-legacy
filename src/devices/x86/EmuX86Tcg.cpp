#define LOG_PREFIX CXBXR_MODULE::X86

#include "devices/x86/EmuX86.h"

#include <atomic>
#include <cassert>
#include <string>

#include "Logging.h"
#include "common/Timer.h"
#include "core/kernel/init/CxbxKrnl.h"
#include "core/kernel/support/Emu.h"
#include "devices/Chihiro/MediaBoard.h"
#include "devices/PCIBus.h"
#include "devices/Xbox.h"
#include "devices/x86/CxbxCpuBackendLoader.h"

extern uint32_t GetAPUTime();
extern std::atomic_bool g_bEnableAllInterrupts;

namespace {
int g_fieldPin = 0;

uint32_t ReadFlash(uint32_t address)
{
	switch (address) {
	case 0x08:
		return 0x2B16D065;
	case 0x78:
		return 0x90;
	default:
		EmuLog(LOG_LEVEL::WARNING, "Read FLASH_ROM (0x%.8X) [unknown address]", address);
		return UINT32_MAX;
	}
}
}

uint32_t EmuX86_IORead(xbox::addr_xt addr, int size)
{
	if (g_bIsChihiro && addr >= 0x4000 && addr <= 0x40ff) {
		return g_MediaBoard->LpcRead(addr, size);
	}

	switch (addr) {
	case 0x8008:
		if (size == sizeof(uint32_t)) {
			return static_cast<uint32_t>(Timer_GetScaledPerformanceCounter(3579545));
		}
		break;
	case 0x80c0:
		if (size == sizeof(uint8_t)) {
			g_fieldPin = (g_fieldPin + 1) & 1;
			return static_cast<uint32_t>(g_fieldPin << 5);
		}
		break;
	default:
		break;
	}

	uint32_t value = 0;
	if (g_PCIBus && g_PCIBus->IORead(addr, &value, size)) {
		return value;
	}
	EmuLog(LOG_LEVEL::WARNING, "TCG IO read 0x%04X/%d [unhandled]", addr, size);
	return 0;
}

void EmuX86_IOWrite(xbox::addr_xt addr, uint32_t value, int size)
{
	if (g_bIsChihiro && addr >= 0x4000 && addr <= 0x40ff) {
		g_MediaBoard->LpcWrite(addr, value, size);
		return;
	}
	if (g_PCIBus && g_PCIBus->IOWrite(addr, value, size)) {
		return;
	}
	EmuLog(LOG_LEVEL::WARNING, "TCG IO write 0x%04X = 0x%08X/%d [unhandled]",
		addr, value, size);
}

uint32_t EmuX86_Read(xbox::addr_xt addr, int size)
{
	if (size != 1 && size != 2 && size != 4) {
		EmuLog(LOG_LEVEL::WARNING, "TCG MMIO read 0x%08X has invalid size %d", addr, size);
		return 0;
	}
	if ((addr & static_cast<xbox::addr_xt>(size - 1)) != 0) {
		EmuLog(LOG_LEVEL::WARNING, "TCG MMIO read 0x%08X/%d is unaligned", addr, size);
	}
	if (addr >= FLASH_DEVICE1_BASE) {
		return ReadFlash((addr - FLASH_DEVICE1_BASE) % KiB(256));
	}
	if (addr == 0xfe80200c) {
		return GetAPUTime();
	}

	uint32_t value = 0;
	if (g_PCIBus && g_PCIBus->MMIORead(addr, &value, size)) {
		return value;
	}
	EmuLog(LOG_LEVEL::WARNING, "TCG MMIO read 0x%08X/%d [unhandled]", addr, size);
	return 0;
}

void EmuX86_Write(xbox::addr_xt addr, uint32_t value, int size)
{
	if (size != 1 && size != 2 && size != 4) {
		EmuLog(LOG_LEVEL::WARNING, "TCG MMIO write 0x%08X has invalid size %d", addr, size);
		return;
	}
	if ((addr & static_cast<xbox::addr_xt>(size - 1)) != 0) {
		EmuLog(LOG_LEVEL::WARNING, "TCG MMIO write 0x%08X/%d is unaligned", addr, size);
	}
	if (addr >= FLASH_DEVICE1_BASE) {
		EmuLog(LOG_LEVEL::WARNING, "TCG write to FLASH_ROM 0x%08X ignored", addr);
		return;
	}
	if (g_PCIBus && g_PCIBus->MMIOWrite(addr, value, size)) {
		return;
	}
	EmuLog(LOG_LEVEL::WARNING, "TCG MMIO write 0x%08X = 0x%08X/%d [unhandled]",
		addr, value, size);
}

int EmuX86_OpcodeSize(uint8_t*)
{
	// Native exception decoding is not part of the TCG execution path. Keep a
	// conservative value for legacy host-only error recovery code.
	return 1;
}

bool EmuX86_DecodeException(LPEXCEPTION_POINTERS)
{
	return false;
}

void EmuX86_Init()
{
	std::string error;
	if (!CxbxCpuBackendInitialize(error)) {
		CxbxrAbort("Unable to initialize the x86 TCG backend: %s", error.c_str());
	}
	EmuLog(LOG_LEVEL::INFO, "Using packaged QEMU/TCG i386 backend");
}
