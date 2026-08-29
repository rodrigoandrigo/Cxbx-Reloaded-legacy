#include "UwpNv2aProducer.h"
#include "UwpDeviceInterrupts.h"
#include "..\..\hle\D3D8\Rendering\UwpD3D11Host.h"
#include "..\..\..\devices\video\nv2a_regs.h"
#include "..\..\hle\D3D8\Rendering\Shaders\CxbxVertexShaderInterpreterState.hlsli"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>

namespace
{
	std::atomic<CxbxUwpNv2aProducer*> g_activeNv2a{ nullptr };
	constexpr std::uint32_t UserOffset = 0x00800000u;
	constexpr std::uint32_t UserChannelStride = 0x10000u;
	constexpr std::uint32_t UserDmaPut = 0x40u;
	constexpr std::uint32_t UserDmaGet = 0x44u;
	constexpr std::uint32_t PmcIntr = 0x100u;
	constexpr std::uint32_t PmcIntrEnable = 0x140u;
	constexpr std::uint32_t PfifoIntr = 0x2100u;
	constexpr std::uint32_t PfifoIntrEnable = 0x2140u;
	constexpr std::uint32_t PfifoMode = 0x2504u;
	constexpr std::uint32_t PfifoCache1Push0 = 0x3200u;
	constexpr std::uint32_t PfifoCache1Push1 = 0x3204u;
	constexpr std::uint32_t PfifoCache1DmaPush = 0x3220u;
	constexpr std::uint32_t PfifoCache1DmaState = 0x3228u;
	constexpr std::uint32_t PfifoCache1DmaInstance = 0x322Cu;
	constexpr std::uint32_t PfifoCache1DmaPut = 0x3240u;
	constexpr std::uint32_t PfifoCache1DmaGet = 0x3244u;
	constexpr std::uint32_t PgraphIntr = 0x400100u;
	constexpr std::uint32_t PgraphIntrEnable = 0x400140u;
	constexpr std::uint32_t PgraphNsource = 0x400108u;
	constexpr std::uint32_t PgraphContextSwitch1 = 0x40014Cu;
	constexpr std::uint32_t PgraphTrappedAddress = 0x400704u;
	constexpr std::uint32_t PgraphTrappedDataLow = 0x400708u;
	constexpr std::uint32_t PgraphInterruptError = 1u << 20;
	constexpr std::uint32_t PgraphSourceNotification = 1u;
	constexpr std::uint32_t PcrtcIntr = 0x600100u;
	constexpr std::uint32_t PcrtcIntrEnable = 0x600140u;
	constexpr std::uint32_t PcrtcRaster = 0x600808u;
	constexpr std::uint64_t VblankPeriodMicros = 16667u;
	constexpr std::uint32_t PtimerTimeLow = 0x009400u;
	constexpr std::uint32_t PtimerTimeHigh = 0x009410u;
	constexpr std::uint32_t PvideoBuffer = 0x008700u;
	constexpr std::uint32_t PvideoStop = 0x008704u;
	constexpr std::uint32_t PraminOffset = 0x00700000u;
	// Retail Xbox reserves PFNs 0x3FE0..0x3FEF for NV2A instance memory.
	constexpr std::uint32_t PraminPhysicalBase = 0x03FE0000u;
	constexpr std::uint32_t PraminPhysicalSize = 0x00010000u;

	float AsFloat(std::uint32_t value) { float result; std::memcpy(&result, &value, 4); return result; }
	float Clamp(float v) { return (std::max)(0.0f, (std::min)(1.0f, v)); }
	std::uint8_t Byte(float v) { return static_cast<std::uint8_t>(Clamp(v) * 255.0f + 0.5f); }
	float Edge(float ax, float ay, float bx, float by, float px, float py) { return (px - ax) * (by - ay) - (py - ay) * (bx - ax); }
	std::uint32_t Part1By1(std::uint32_t x) { x &= 0x0000ffff; x = (x | x << 8) & 0x00ff00ff; x = (x | x << 4) & 0x0f0f0f0f; x = (x | x << 2) & 0x33333333; return (x | x << 1) & 0x55555555; }
	std::uint32_t Morton2(std::uint32_t x, std::uint32_t y) { return Part1By1(x) | (Part1By1(y) << 1); }

	bool Compare(std::uint32_t function, float source, float reference)
	{
		switch (function) {
		case 0x0200: return false; case 0x0201: return source < reference; case 0x0202: return source == reference;
		case 0x0203: return source <= reference; case 0x0204: return source > reference; case 0x0205: return source != reference;
		case 0x0206: return source >= reference; default: return true;
		}
	}

	std::uint32_t ApplyStencilOp(std::uint32_t operation, std::uint32_t current, std::uint32_t reference)
	{
		switch (operation) {
		case 0x0000: return 0; case 0x1E01: return reference; case 0x1E02: return (std::min)(255u, current + 1);
		case 0x1E03: return current ? current - 1 : 0; case 0x150A: return current ^ 0xFFu;
		case 0x8507: return (current + 1) & 0xFFu; case 0x8508: return (current - 1) & 0xFFu;
		default: return current;
		}
	}

	CxbxUwpNv2aProducer::ColorF Unpack(std::uint32_t argb)
	{
		return { ((argb >> 16) & 255) / 255.0f, ((argb >> 8) & 255) / 255.0f,
			(argb & 255) / 255.0f, ((argb >> 24) & 255) / 255.0f };
	}
}

CxbxUwpNv2aProducer::CxbxUwpNv2aProducer(std::uint8_t* ram, std::size_t ramSize, LogCallback logger)
	: m_ram(ram), m_ramSize(ramSize), m_logger(logger)
{
	ResetState();
	g_activeNv2a.store(this, std::memory_order_release);
}

CxbxUwpNv2aProducer::~CxbxUwpNv2aProducer()
{
	auto* expected = this;
	g_activeNv2a.compare_exchange_strong(expected, nullptr, std::memory_order_acq_rel);
}

void CxbxUwpNv2aProducer::ConfigureDisplay(std::uint32_t mode,
	std::uint32_t format, std::uint32_t pitch, std::uint32_t frameBuffer)
{
	const std::uint32_t crtc = (mode >> 8) & 0xFFu;
	switch (crtc) {
	case 2: case 4: case 6: case 8: m_width = 720; break;
	case 10: m_width = 1280; break;
	case 12: m_width = 1920; break;
	default: m_width = 640; break;
	}
	switch (crtc) {
	case 5: case 6: case 14: case 16: m_height = 576; break;
	case 10: m_height = 720; break;
	case 12: m_height = 1080; break;
	default: m_height = 480; break;
	}
	m_colorOffset = PhysicalAddress(frameBuffer);
	const bool sixteenBit = format == 0x10u || format == 0x11u || format == 0x1Cu;
	m_colorPitch = pitch ? pitch : m_width * (sixteenBit ? 2u : 4u);
	if (format == 0x11u) m_surfaceFormat = 3u;
	else if (format == 0x10u || format == 0x1Cu) m_surfaceFormat = 2u;
	else m_surfaceFormat = 5u;
	m_registers[0x600800u] = frameBuffer;
	SubmitSurface();
}

bool CxbxUwpConfigureNv2aDisplay(std::uint32_t mode, std::uint32_t format,
	std::uint32_t pitch, std::uint32_t frameBuffer)
{
	auto* producer = g_activeNv2a.load(std::memory_order_acquire);
	if (!producer) return false;
	producer->ConfigureDisplay(mode, format, pitch, frameBuffer);
	return true;
}

bool CxbxUwpWriteNv2aRegister(std::uint32_t offset, std::uint32_t value)
{
	auto* producer = g_activeNv2a.load(std::memory_order_acquire);
	if (!producer || offset >= CxbxUwpNv2aProducer::MmioSize) return false;
	producer->Write32(CxbxUwpNv2aProducer::MmioBase + offset, value);
	return true;
}

void CxbxUwpNv2aProducer::ResetState()
{
	for (auto& value : m_inlineAttributes) value = {};
	m_inlineAttributes[3] = { 1, 1, 1, 1 };
	for (auto& value : m_inlineAttributeMask) value = 0;
	m_pgraphMethods.fill(0);
	m_pgraphTrapPending = false;
	m_interruptLineAsserted = false;
	m_pendingDmaPut = 0;
	m_pendingDmaChannel = 0;
	m_dmaCallStack.fill(0);
	m_dmaStackDepth = m_dmaMethod = m_dmaSubchannel = m_dmaRemaining = 0;
	m_dmaIncrement = true;
	m_dmaParserSuspended = false;
	m_loggedFirstPushBuffer = false;
	m_loggedFirstFrame = false;
	m_vblankCount = 0;
	const auto now = std::chrono::steady_clock::now().time_since_epoch();
	m_nextVblankMicros = static_cast<std::uint64_t>(
		std::chrono::duration_cast<std::chrono::microseconds>(now).count()) + VblankPeriodMicros;
	m_registers[PmcIntrEnable] = 1;
	// Match NV2ADevice::Initialize: PFIFO/PGRAPH masks are programmed by the
	// miniport. Enabling every error at reset makes normal initialization traps
	// visible to the D3D runtime before its ISR state is ready.
	m_registers[PfifoIntrEnable] = 0;
	m_registers[PgraphIntrEnable] = 0;
	m_registers[PcrtcIntrEnable] = 1;
	m_registers[0x002210u]=0x03000100u;m_registers[0x002214u]=0x00890110u;m_registers[0x680500u]=0x00011C01u;m_registers[0x680504u]=0;m_registers[0x680508u]=0x0003C20Du;m_registers[0x009200u]=1;m_registers[0x009210u]=1;
}

std::uint8_t CxbxUwpNv2aProducer::Read8(std::uint32_t address) const { return static_cast<std::uint8_t>(Read32(address & ~3u) >> ((address & 3u) * 8)); }
std::uint16_t CxbxUwpNv2aProducer::Read16(std::uint32_t address) const { return static_cast<std::uint16_t>(Read32(address & ~3u) >> ((address & 2u) * 8)); }
std::uint64_t CxbxUwpNv2aProducer::Read64(std::uint32_t address) const { return Read32(address) | (static_cast<std::uint64_t>(Read32(address + 4)) << 32); }

std::uint32_t CxbxUwpNv2aProducer::Read32(std::uint32_t address) const
{
	if (address < MmioBase || address - MmioBase >= MmioSize) return 0xFFFFFFFFu;
	std::uint32_t offset = address - MmioBase;if(offset>=0x00C00000u)offset-=0x00400000u;
	if (offset == PfifoCache1DmaGet) return m_dmaGet;
	if (offset >= UserOffset) {
		const auto channelOffset = offset % UserChannelStride;
		const auto channel = (offset - UserOffset) / UserChannelStride;
		const auto activeChannel = Register(PfifoCache1Push1) & 0x1Fu;
		if (channel < 32 && channel == activeChannel && (Register(PfifoMode) & (1u << channel)) != 0) {
			if (channelOffset == UserDmaGet) return m_dmaGet;
			if (channelOffset == UserDmaPut) return Register(PfifoCache1DmaPut);
		}
	}
	if (offset == PmcIntr) {
		// PMC reports only enabled sub-unit sources. Returning raw pending bits
		// makes the stock ISR process masked/stale errors when an unrelated source
		// (typically PCRTC vblank) raises the shared GPU interrupt line.
		return ((Register(PfifoIntr) & Register(PfifoIntrEnable)) ? 0x100u : 0u) |
			((Register(PgraphIntr) & Register(PgraphIntrEnable)) ? 0x1000u : 0u) |
			((Register(PcrtcIntr) & Register(PcrtcIntrEnable)) ? 0x01000000u : 0u);
	}
	if(offset==0)return 0x02A000A2u;if(offset==0x002400u)return 0x10u;if(offset==0x100200u)return 3u;if(offset==0x10020Cu)return static_cast<std::uint32_t>(m_ramSize);if(offset==0x100410u)return 0u;if(offset==0x68050Cu)return 0x000F0000u;
	if (offset == PtimerTimeLow || offset == PtimerTimeHigh) {
		const auto now = std::chrono::steady_clock::now().time_since_epoch();
		const auto ticks = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count() * 33750000ull / 1000000000ull);
		return offset == PtimerTimeLow ? static_cast<std::uint32_t>(ticks << 5) : static_cast<std::uint32_t>(ticks >> 27);
	}
	if (offset == PcrtcRaster) {
		const auto now = std::chrono::steady_clock::now().time_since_epoch();
		const auto micros = static_cast<std::uint64_t>(
			std::chrono::duration_cast<std::chrono::microseconds>(now).count());
		const std::uint32_t visibleLines = m_height ? m_height : 480u;
		// NTSC has 480 visible lines in a 525-line frame. Preserve a similarly
		// sized blanking interval for other modes so bit 16 can actually become
		// visible to titles polling NV_PCRTC_RASTER.
		const std::uint32_t totalLines = visibleLines + (std::max)(45u, visibleLines * 3u / 32u);
		const auto phase = micros % VblankPeriodMicros;
		const auto line = static_cast<std::uint32_t>(phase * totalLines / VblankPeriodMicros);
		return (line & 0x7FFu) |
			(line >= visibleLines ? 1u << 16 : 0u) |
			(static_cast<std::uint32_t>(m_vblankCount & 1u) << 20);
	}
	return Register(offset & ~3u);
}

void CxbxUwpNv2aProducer::Write8(std::uint32_t address, std::uint8_t value)
{
	const auto aligned = address & ~3u, shift = (address & 3u) * 8;
	Write32(aligned, (Read32(aligned) & ~(0xFFu << shift)) | (static_cast<std::uint32_t>(value) << shift));
}
void CxbxUwpNv2aProducer::Write16(std::uint32_t address, std::uint16_t value)
{
	const auto aligned = address & ~3u, shift = (address & 2u) * 8;
	Write32(aligned, (Read32(aligned) & ~(0xFFFFu << shift)) | (static_cast<std::uint32_t>(value) << shift));
}
void CxbxUwpNv2aProducer::Write64(std::uint32_t address, std::uint64_t value) { Write32(address, static_cast<std::uint32_t>(value)); Write32(address + 4, static_cast<std::uint32_t>(value >> 32)); }

void CxbxUwpNv2aProducer::Write32(std::uint32_t address, std::uint32_t value)
{
	if (address < MmioBase || address - MmioBase >= MmioSize) return;
	std::uint32_t offset = address - MmioBase;if(offset>=0x00C00000u)offset-=0x00400000u;
	if (offset == PfifoIntr || offset == PgraphIntr || offset == PcrtcIntr) m_registers[offset] &= ~value;
	else {
		const std::uint32_t alignedOffset = offset & ~3u;
		m_registers[alignedOffset] = value;
		// The stock miniport can access RAMIN through either the PRAMIN aperture
		// or the claimed physical instance-memory range. Keep both views coherent.
		if (alignedOffset >= PraminOffset && alignedOffset - PraminOffset < PraminPhysicalSize) {
			const std::uint64_t physical = static_cast<std::uint64_t>(PraminPhysicalBase) +
				(alignedOffset - PraminOffset);
			if (m_ram && physical + sizeof(value) <= m_ramSize)
				std::memcpy(m_ram + physical, &value, sizeof(value));
		}
	}
	if (offset == PmcIntrEnable || offset == PfifoIntr || offset == PfifoIntrEnable ||
		offset == PgraphIntr || offset == PgraphIntrEnable ||
		offset == PcrtcIntr || offset == PcrtcIntrEnable) UpdateInterruptLine();
	if (offset == PfifoCache1DmaGet) m_dmaGet = value & ~3u;
	if (offset == PvideoStop) m_registers[PvideoBuffer] = 0;
	if (offset >= UserOffset) {
		const auto channelOffset = offset % UserChannelStride;
		const auto channel = (offset - UserOffset) / UserChannelStride;
		const auto activeChannel = Register(PfifoCache1Push1) & 0x1Fu;
		if (channel < 32 && channel == activeChannel && (Register(PfifoMode) & (1u << channel)) != 0) {
			if (channelOffset == UserDmaGet) {
				m_dmaGet = value & ~3u;
				m_registers[PfifoCache1DmaGet] = m_dmaGet;
			}
			if (channelOffset == UserDmaPut) {
				m_registers[PfifoCache1DmaPut] = value & ~3u;
				if (CanRunDmaChannel(channel)) ConsumePushBuffer(value & ~3u, channel);
			}
		}
	}
	if (offset == PfifoMode || offset == PfifoCache1Push0 || offset == PfifoCache1Push1 ||
		offset == PfifoCache1DmaPush || offset == PfifoCache1DmaInstance) TryRunCurrentDmaChannel();
	// The hardware PFIFO puller sleeps while a Kelvin software notification is
	// outstanding. Resume at the word following the NOP only after the guest ISR
	// acknowledges PGRAPH_INTR_ERROR. Calling the parser here is non-blocking and
	// preserves the single executor-thread architecture used by UWP.
	if (offset == PgraphIntr && (value & PgraphInterruptError) != 0 &&
		m_pgraphTrapPending && (Register(PgraphIntr) & PgraphInterruptError) == 0) {
		m_pgraphTrapPending = false;
		const auto pendingPut = m_pendingDmaPut;
		const auto pendingChannel = m_pendingDmaChannel;
		m_pendingDmaPut = 0;
		ConsumePushBuffer(pendingPut, pendingChannel);
	}
}

bool CxbxUwpNv2aProducer::CanRunDmaChannel(std::uint32_t channel) const
{
	if (channel >= 32 || (Register(PfifoMode) & (1u << channel)) == 0) return false;
	const auto push1 = Register(PfifoCache1Push1);
	if ((push1 & 0x1Fu) != channel || (push1 & 0x100u) == 0) return false;
	if ((Register(PfifoCache1Push0) & 1u) == 0) return false;
	const auto dmaPush = Register(PfifoCache1DmaPush);
	return (dmaPush & 1u) != 0 && (dmaPush & 0x1000u) == 0;
}

void CxbxUwpNv2aProducer::TryRunCurrentDmaChannel()
{
	const auto channel = Register(PfifoCache1Push1) & 0x1Fu;
	const auto put = Register(PfifoCache1DmaPut) & ~3u;
	if (put != m_dmaGet && CanRunDmaChannel(channel)) ConsumePushBuffer(put, channel);
}

void CxbxUwpNv2aProducer::SetDmaPusherError(std::uint32_t error,
	std::uint32_t get, std::uint32_t put, std::uint32_t word)
{
	m_registers[PfifoCache1DmaState] =
		(Register(PfifoCache1DmaState) & ~0xE0000000u) | ((error & 7u) << 29);
	m_registers[PfifoCache1DmaPush] = Register(PfifoCache1DmaPush) | 0x1000u;
	if (m_logger) {
		const auto instance = (Register(PfifoCache1DmaInstance) & 0xFFFFu) << 4;
		const auto flags = Register(0x700000u + instance);
		const auto limit = Register(0x700004u + instance);
		const auto start = Register(0x700008u + instance);
		const auto address = Register(0x70000Cu + instance);
		const auto frame = ResolveDmaFrame(instance);
		const auto base = PhysicalAddress((frame & 0xFFFFF000u) | ((flags >> 20) & 0xFFFu));
		char line[360] = {};
		sprintf_s(line,
			"[uwp-nv2a:pfifo:error] codigo=%u canal=%u GET=%08X PUT=%08X WORD=%08X instancia=%05X flags=%08X start=%08X address=%08X frame=%08X base=%08X limite=%08X.\r\n",
			error & 7u, m_dmaChannel, get, put, word, instance, flags, start, address, frame, base, limit);
		m_logger(line);
	}
}

std::uint32_t CxbxUwpNv2aProducer::PhysicalAddress(std::uint32_t address) const
{
	// Xbox contiguous virtual aliases (0x80000000/0xA0000000) preserve their
	// low physical bits. DMA object offsets supplied directly are already physical.
	if (address >= 0x80000000u) address &= 0x07FFFFFFu;
	return address;
}

bool CxbxUwpNv2aProducer::ResolveHandle(std::uint32_t handle,std::uint32_t channel,std::uint32_t& instance,std::uint32_t& objectClass) const
{
	auto readReg = [this](std::uint32_t key, std::uint32_t fallback = 0u) {
		auto found = m_registers.find(key);
		if (found != m_registers.end()) return found->second;
		if (key >= PraminOffset && key - PraminOffset < PraminPhysicalSize) return Register(key);
		return fallback;
	};
	const auto ramht=readReg(0x002210u,0x03000100u);const unsigned size=1u<<(((ramht>>16)&3)+12),bits=static_cast<unsigned>(std::log2(size))-1;std::uint32_t hash=0,value=handle;while(value){hash^=value&((1u<<bits)-1);value>>=bits;}hash^=channel<<(bits-4);const auto base=(ramht&0x1F0u)<<8;const unsigned probes=16u<<((ramht>>24)&3);
	for(unsigned probe=0;probe<probes;probe++){const auto entry=(hash+probe)&(size/8-1),address=PraminOffset+base+entry*8;const auto storedHandle=readReg(address),context=readReg(address+4);if(storedHandle==handle&&(context&0x80000000u)){instance=(context&0xFFFFu)<<4;objectClass=readReg(PraminOffset+instance)&0xFFFu;return true;}}return false;
}

std::uint32_t CxbxUwpNv2aProducer::ResolveDmaBase(std::uint32_t instance,std::uint32_t* limit) const
{
	const auto flags=Register(PraminOffset+instance),frame=ResolveDmaFrame(instance);if(limit)*limit=Register(PraminOffset+instance+4)+1;return PhysicalAddress((frame&0xFFFFF000u)|((flags>>20)&0xFFFu));
}

std::uint32_t CxbxUwpNv2aProducer::ResolveDmaFrame(std::uint32_t instance) const
{
	const auto start = Register(PraminOffset + instance + 8);
	const auto address = Register(PraminOffset + instance + 12);
	// xemu-style objects keep the frame in START. The stock Xbox miniport also
	// emits the documented four-DWORD form where START contains small paging
	// metadata and ADDRESS contains the physical base.
	if ((start & 0xFFFFF000u) != 0 || (address & 0xFFFFF000u) == 0) return start;
	return address;
}

bool CxbxUwpNv2aProducer::ReadBytes(std::uint64_t address, void* destination, std::size_t size) const
{
	address = PhysicalAddress(static_cast<std::uint32_t>(address));
	if (!m_ram || address > m_ramSize || size > m_ramSize - static_cast<std::size_t>(address)) return false;
	std::memcpy(destination, m_ram + address, size); return true;
}
bool CxbxUwpNv2aProducer::ReadWord(std::uint32_t address, std::uint32_t& value) const { return !(address & 3u) && ReadBytes(address, &value, 4); }

void CxbxUwpNv2aProducer::ConsumePushBuffer(std::uint32_t put, std::uint32_t channel)
{
	if (m_pgraphTrapPending) {
		// PUT may advance while PFIFO is stalled; retain the newest producer edge.
		m_pendingDmaPut = put;
		m_pendingDmaChannel = channel;
		return;
	}
	m_dmaChannel = channel & 0x1Fu;
	m_pendingDmaPut = put;
	m_pendingDmaChannel = channel;
	std::uint32_t dmaBase = 0, dmaLimit = static_cast<std::uint32_t>((std::min)(m_ramSize, static_cast<std::size_t>(0xFFFFFFFFu)));
	auto dmaInstanceIt = m_registers.find(PfifoCache1DmaInstance);
	if (dmaInstanceIt != m_registers.end()) {
		const auto instance = (dmaInstanceIt->second & 0xFFFFu) << 4;
		const auto flags = Register(PraminOffset + instance);
		const auto limit = Register(PraminOffset + instance + 4);
		if (flags || limit) {
			const auto frame=ResolveDmaFrame(instance);
			dmaBase=PhysicalAddress((frame&0xFFFFF000u)|((flags>>20)&0xFFFu));
			dmaLimit=limit+1;
		}
	}
	if (!m_loggedFirstPushBuffer && m_logger) {
		char line[192] = {};
		sprintf_s(line, "[uwp-nv2a] Primeiro push buffer: canal=%u base=%08X GET=%08X PUT=%08X limite=%08X.\r\n",
			m_dmaChannel, dmaBase, m_dmaGet, put, dmaLimit);
		m_logger(line);
		m_loggedFirstPushBuffer = true;
	}
	std::uint32_t cursor = m_dmaGet;
	auto callStack = m_dmaCallStack;
	std::uint32_t stackDepth = m_dmaParserSuspended ? m_dmaStackDepth : 0;
	std::uint32_t method = m_dmaParserSuspended ? m_dmaMethod : 0;
	std::uint32_t subchannel = m_dmaParserSuspended ? m_dmaSubchannel : 0;
	std::uint32_t remaining = m_dmaParserSuspended ? m_dmaRemaining : 0;
	bool increment = m_dmaParserSuspended ? m_dmaIncrement : true;
	m_dmaParserSuspended = false;
	for (std::uint32_t words = 0; words < 0x100000 && cursor != put; ++words) {
		std::uint32_t word = 0;
		if (cursor >= dmaLimit || !ReadWord(dmaBase + cursor, word)) {
			SetDmaPusherError(6, cursor, put, 0);
			break;
		}
		cursor += 4;
		if (remaining) {
			ExecuteMethod(subchannel, method, word);
			if (increment) method += 4;
			--remaining;
			if (m_pgraphTrapPending) break;
			continue;
		}
		if ((word & 0xE0000003u) == 0x20000000u) { cursor = word & 0x1FFFFFFCu; continue; }
		if ((word & 3u) == 1u) { cursor = word & 0xFFFFFFFCu; continue; }
		if ((word & 3u) == 2u) {
			if (stackDepth) { SetDmaPusherError(1, cursor, put, word); break; }
			callStack[stackDepth++] = cursor; cursor = word & 0xFFFFFFFCu; continue;
		}
		if (word == 0x00020000u) {
			if (stackDepth) cursor = callStack[--stackDepth];
			else { SetDmaPusherError(3, cursor, put, word); break; }
			continue;
		}
		if ((word & 0xE0030003u) == 0u || (word & 0xE0030003u) == 0x40000000u) {
			method = word & 0x1FFCu; subchannel = (word >> 13) & 7u; remaining = (word >> 18) & 0x7FFu; increment = !(word & 0x40000000u); continue;
		}
		SetDmaPusherError(4, cursor, put, word);
		break;
	}
	m_dmaGet = cursor;
	m_registers[PfifoCache1DmaGet] = cursor;
	if (m_pgraphTrapPending) {
		m_dmaCallStack = callStack;
		m_dmaStackDepth = stackDepth;
		m_dmaMethod = method;
		m_dmaSubchannel = subchannel;
		m_dmaRemaining = remaining;
		m_dmaIncrement = increment;
		m_dmaParserSuspended = true;
	} else {
		m_pendingDmaPut = 0;
		m_dmaStackDepth = m_dmaRemaining = 0;
		m_dmaParserSuspended = false;
	}
	// Reaching PUT is the normal PFIFO idle state, not RUNOUT and not an
	// interrupt. Only parsing/DMA failures above set PFIFO status bits.
	UpdateInterruptLine();
}

void CxbxUwpNv2aProducer::BeginPrimitive(std::uint32_t mode)
{
	m_beginEnd = mode; m_indices.clear(); m_inlineArray.clear(); m_inlineVertices.clear();
}

void CxbxUwpNv2aProducer::EndPrimitive()
{
	if (!m_indices.empty()) DrawIndexed();
	else if (!m_inlineVertices.empty()) DrawVertices(m_inlineVertices, nullptr);
	else if (!m_inlineArray.empty()) { std::vector<Vertex> vertices; if (DecodeInlineVertices(vertices)) DrawVertices(vertices, nullptr); }
	m_beginEnd = 0; SubmitSurface();
}

void CxbxUwpNv2aProducer::ExecuteMethod(std::uint32_t subchannel, std::uint32_t method, std::uint32_t value)
{
	if (method < 0x2000) m_pgraphMethods[method >> 2] = value;
	if (method == 0) {
		std::uint32_t instance=0,objectClass=0;
		if(!ResolveHandle(value,m_dmaChannel,instance,objectClass)){instance=value;objectClass=Register(PraminOffset+instance)&0xFFFu;}
		m_subchannelObject[subchannel&7]=instance;
		m_subchannelClass[subchannel&7]=objectClass;
		// Mirror the active graphics context used by the stock ISR when it builds
		// its error/notification record.
		m_registers[PgraphContextSwitch1] = objectClass & NV_PGRAPH_CTX_SWITCH1_GRCLASS;
		return;
	}
	m_registers[PgraphContextSwitch1] = m_subchannelClass[subchannel&7] & NV_PGRAPH_CTX_SWITCH1_GRCLASS;
	const auto objectClass=m_subchannelClass[subchannel&7];
	if(objectClass==NV_CONTEXT_SURFACES_2D){std::uint32_t instance=0,ignored=0;switch(method){case NV062_SET_CONTEXT_DMA_IMAGE_SOURCE:if(ResolveHandle(value,0,instance,ignored))m_surface2DSourceDma=instance;else m_surface2DSourceDma=value;break;case NV062_SET_CONTEXT_DMA_IMAGE_DESTIN:if(ResolveHandle(value,0,instance,ignored))m_surface2DDestinationDma=instance;else m_surface2DDestinationDma=value;break;case NV062_SET_COLOR_FORMAT:m_surface2DFormat=value;break;case NV062_SET_PITCH:m_surface2DSourcePitch=value&0xFFFF;m_surface2DDestinationPitch=value>>16;break;case NV062_SET_OFFSET_SOURCE:m_surface2DSourceOffset=value&0x07FFFFFF;break;case NV062_SET_OFFSET_DESTIN:m_surface2DDestinationOffset=value&0x07FFFFFF;break;}return;}
	if(objectClass==NV_IMAGE_BLIT){switch(method){case NV09F_SET_OPERATION:m_blitOperation=value;break;case NV09F_CONTROL_POINT_IN:m_blitIn=value;break;case NV09F_CONTROL_POINT_OUT:m_blitOut=value;break;case NV09F_SIZE:m_blitSize=value;Execute2DBlit();break;}return;}
	if (method >= NV097_SET_VERTEX_DATA_ARRAY_OFFSET && method < NV097_SET_VERTEX_DATA_ARRAY_OFFSET + 64) { m_vertexArrays[(method - NV097_SET_VERTEX_DATA_ARRAY_OFFSET) / 4].offset = value; return; }
	if (method >= NV097_SET_VERTEX_DATA_ARRAY_FORMAT && method < NV097_SET_VERTEX_DATA_ARRAY_FORMAT + 64) { m_vertexArrays[(method - NV097_SET_VERTEX_DATA_ARRAY_FORMAT) / 4].format = value; return; }
	if (method >= NV097_SET_TEXTURE_OFFSET && method < NV097_SET_TEXTURE_OFFSET + 4 * 0x40) {
		auto& t = m_textures[(method - NV097_SET_TEXTURE_OFFSET) / 0x40]; const auto field = (method - NV097_SET_TEXTURE_OFFSET) & 0x3F;
		switch (field) { case 0: t.offset=value; break; case 4:t.format=value;break; case 8:t.address=value;break; case 0xC:t.control0=value;break; case 0x10:t.control1=value;break; case 0x14:t.filter=value;break; case 0x1C:t.rect=value;break; case 0x20:t.palette=value;break; case 0x24:t.borderColor=value;break; }
		return;
	}
	if (method >= NV097_SET_VIEWPORT_OFFSET && method < NV097_SET_VIEWPORT_OFFSET + 16) { m_viewportOffset[(method - NV097_SET_VIEWPORT_OFFSET) / 4] = AsFloat(value); return; }
	if (method >= NV097_SET_VIEWPORT_SCALE && method < NV097_SET_VIEWPORT_SCALE + 16) { m_viewportScale[(method - NV097_SET_VIEWPORT_SCALE) / 4] = AsFloat(value); return; }
	if (method >= NV097_SET_FOG_PARAMS && method < NV097_SET_FOG_PARAMS + 12) { m_fogParams[(method-NV097_SET_FOG_PARAMS)/4]=AsFloat(value);return; }
	if (method >= NV097_SET_TRANSFORM_PROGRAM && method < NV097_SET_TRANSFORM_PROGRAM + 32 * 4) { const auto slot=(method-NV097_SET_TRANSFORM_PROGRAM)/4;if(m_programLoad<m_transformProgram.size())m_transformProgram[m_programLoad][slot&3]=value;if((slot&3)==3&&m_programLoad+1<m_transformProgram.size())++m_programLoad;return; }
	if (method >= NV097_SET_TRANSFORM_CONSTANT && method < NV097_SET_TRANSFORM_CONSTANT + 32 * 4) { const auto slot=(method-NV097_SET_TRANSFORM_CONSTANT)/4;if(m_constantLoad<m_transformConstants.size())(&m_transformConstants[m_constantLoad].x)[slot&3]=AsFloat(value);if((slot&3)==3&&m_constantLoad+1<m_transformConstants.size())++m_constantLoad;return; }
	if (method >= NV097_SET_VERTEX_DATA2F_M && method < NV097_SET_VERTEX_DATA2F_M + 16 * 8) {
		const auto slot=(method-NV097_SET_VERTEX_DATA2F_M)/8, component=((method-NV097_SET_VERTEX_DATA2F_M)&4)/4; (&m_inlineAttributes[slot].x)[component]=AsFloat(value); m_inlineAttributeMask[slot]|=1u<<component; if(slot==0&&component==1)EmitInlineVertex(); return;
	}
	if (method >= NV097_SET_VERTEX_DATA4F_M && method < NV097_SET_VERTEX_DATA4F_M + 16 * 16) {
		const auto slot=(method-NV097_SET_VERTEX_DATA4F_M)/16, component=((method-NV097_SET_VERTEX_DATA4F_M)&15)/4; (&m_inlineAttributes[slot].x)[component]=AsFloat(value); m_inlineAttributeMask[slot]|=1u<<component; if(slot==0&&component==3)EmitInlineVertex(); return;
	}
	if (method >= NV097_SET_VERTEX_DATA4UB && method < NV097_SET_VERTEX_DATA4UB + 64) {
		const auto slot=(method-NV097_SET_VERTEX_DATA4UB)/4; m_inlineAttributes[slot]={ (value&255)/255.f,((value>>8)&255)/255.f,((value>>16)&255)/255.f,((value>>24)&255)/255.f }; m_inlineAttributeMask[slot]=15; if(slot==0)EmitInlineVertex(); return;
	}
	if (method >= NV097_SET_VERTEX_DATA2S && method < NV097_SET_VERTEX_DATA2S + 64) {
		const auto slot=(method-NV097_SET_VERTEX_DATA2S)/4; m_inlineAttributes[slot].x=static_cast<std::int16_t>(value)/32767.f; m_inlineAttributes[slot].y=static_cast<std::int16_t>(value>>16)/32767.f; m_inlineAttributeMask[slot]=3; if(slot==0)EmitInlineVertex(); return;
	}
	switch (method) {
	case NV097_SET_SURFACE_CLIP_HORIZONTAL: m_clipX=value&0xFFFF; m_width=value>>16; break;
	case NV097_SET_SURFACE_CLIP_VERTICAL: m_clipY=value&0xFFFF; m_height=value>>16; break;
	case NV097_SET_SURFACE_FORMAT: m_surfaceFormat=value;if(((value>>8)&15u)==2){const auto logWidth=(value>>16)&255u,logHeight=(value>>24)&255u;if(logWidth<16)m_width=1u<<logWidth;if(logHeight<16)m_height=1u<<logHeight;}break;
	case NV097_SET_SURFACE_PITCH: m_colorPitch=value&0xFFFF; m_zetaPitch=value>>16; break;
	case NV097_SET_SURFACE_COLOR_OFFSET: m_colorOffset=PhysicalAddress(value); break;
	case NV097_SET_SURFACE_ZETA_OFFSET: m_zetaOffset=PhysicalAddress(value); break;
	case NV097_SET_BEGIN_END: if(value)BeginPrimitive(value); else EndPrimitive(); break;
	case NV097_DRAW_ARRAYS: DrawArrays(value&0x00FFFFFFu,((value>>24)&255)+1); break;
	case NV097_ARRAY_ELEMENT16: m_indices.push_back(value&0xFFFF);m_indices.push_back(value>>16); break;
	case NV097_ARRAY_ELEMENT32: m_indices.push_back(value); break;
	case NV097_INLINE_ARRAY: m_inlineArray.push_back(value); break;
	case NV097_SET_ALPHA_TEST_ENABLE:m_alphaTest=value!=0;break; case NV097_SET_BLEND_ENABLE:m_blend=value!=0;break;
	case NV097_SET_CULL_FACE_ENABLE:m_cull=value!=0;break; case NV097_SET_DEPTH_TEST_ENABLE:m_depthTest=value!=0;break;
	case NV097_SET_STENCIL_TEST_ENABLE:m_stencilTest=value!=0;break; case NV097_SET_ALPHA_FUNC:m_alphaFunc=value;break; case NV097_SET_ALPHA_REF:m_alphaRef=value;break;
	case NV097_SET_BLEND_FUNC_SFACTOR:m_blendSrc=value;break; case NV097_SET_BLEND_FUNC_DFACTOR:m_blendDst=value;break; case NV097_SET_BLEND_COLOR:m_blendColor=value;break; case NV097_SET_BLEND_EQUATION:m_blendEquation=value;break;
	case NV097_SET_DEPTH_FUNC:m_depthFunc=value;break; case NV097_SET_COLOR_MASK:m_colorMask=value;break; case NV097_SET_DEPTH_MASK:m_depthWrite=value!=0;break;
	case NV097_SET_STENCIL_MASK:m_stencilWriteMask=value;break; case NV097_SET_STENCIL_FUNC:m_stencilFunc=value;break; case NV097_SET_STENCIL_FUNC_REF:m_stencilRef=value;break; case NV097_SET_STENCIL_FUNC_MASK:m_stencilFuncMask=value;break;
	case NV097_SET_STENCIL_OP_FAIL:m_stencilFail=value;break; case NV097_SET_STENCIL_OP_ZFAIL:m_stencilZFail=value;break; case NV097_SET_STENCIL_OP_ZPASS:m_stencilZPass=value;break;
	case NV097_SET_CULL_FACE:m_cullFace=value;break; case NV097_SET_FRONT_FACE:m_frontFace=value;break;
	case NV097_SET_FRONT_POLYGON_MODE:m_frontPolygonMode=value;break;case NV097_SET_BACK_POLYGON_MODE:m_backPolygonMode=value;break;case NV097_SET_SHADE_MODE:m_shadeMode=value;break;
	case NV097_SET_POINT_SIZE:m_pointSize=value;break;case NV097_SET_LINE_WIDTH:m_lineWidth=value;break;case NV097_SET_LOGIC_OP_ENABLE:m_logicOpEnabled=value!=0;break;case NV097_SET_LOGIC_OP:m_logicOp=value;break;
	case NV097_SET_FOG_ENABLE:m_fogEnabled=value!=0;break;case NV097_SET_FOG_MODE:m_fogMode=value;break;case NV097_SET_FOG_COLOR:m_fogColor=value;break;
	case NV097_SET_COLOR_CLEAR_VALUE:m_colorClearValue=value;break; case NV097_SET_ZSTENCIL_CLEAR_VALUE:m_zstencilClearValue=value;break;
	case NV097_SET_CLEAR_RECT_HORIZONTAL:m_clearRectHorizontal=value;break; case NV097_SET_CLEAR_RECT_VERTICAL:m_clearRectVertical=value;break; case NV097_CLEAR_SURFACE:ClearSurface(value);break;
	case NV097_SET_SHADER_STAGE_PROGRAM:m_shaderStageProgram=value;break; case NV097_SET_SHADER_OTHER_STAGE_INPUT:m_shaderOtherStageInput=value;break; case NV097_SET_COMBINER_CONTROL:m_combinerControl=value;break;
	case NV097_SET_TRANSFORM_PROGRAM_LOAD:m_programLoad=value&0xFF;break; case NV097_SET_TRANSFORM_PROGRAM_START:m_programStart=value&0xFF;break; case NV097_SET_TRANSFORM_CONSTANT_LOAD:m_constantLoad=value&0xFF;break; case NV097_SET_TRANSFORM_EXECUTION_MODE:m_transformMode=value&3;break;
	case NV097_SET_CONTEXT_DMA_SEMAPHORE:{std::uint32_t instance=0,ignored=0;m_semaphoreDma=ResolveHandle(value,0,instance,ignored)?instance:value;break;}
	case NV097_SET_CONTEXT_DMA_REPORT:{std::uint32_t instance=0,ignored=0;m_reportDma=ResolveHandle(value,0,instance,ignored)?instance:value;break;}
	case NV097_SET_SEMAPHORE_OFFSET:m_semaphoreOffset=value;break;
	case NV097_BACK_END_WRITE_SEMAPHORE_RELEASE:{std::uint32_t limit=0;const auto address=static_cast<std::uint64_t>(ResolveDmaBase(m_semaphoreDma,&limit))+m_semaphoreOffset;if(m_semaphoreOffset+4<=limit&&address+4<=m_ramSize)std::memcpy(m_ram+address,&value,4);break;}
	case NV097_CLEAR_REPORT_VALUE:m_zpassCount=0;break;case NV097_SET_ZPASS_PIXEL_COUNT_ENABLE:m_zpassCountEnabled=value!=0;break;
	case NV097_GET_REPORT:{const auto offset=value&0xFFFFFFu;std::uint32_t limit=0;const auto address=static_cast<std::uint64_t>(ResolveDmaBase(m_reportDma,&limit))+offset;if(offset+16<=limit&&address+16<=m_ramSize){const auto now=std::chrono::steady_clock::now().time_since_epoch();const auto timestamp=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count()/100);std::uint32_t done=0;std::memcpy(m_ram+address,&timestamp,8);std::memcpy(m_ram+address+8,&m_zpassCount,4);std::memcpy(m_ram+address+12,&done,4);}break;}
	case NV097_NO_OPERATION:
		if (value) {
			// Xbox uses a non-zero Kelvin NOP as a software notification. The
			// stock ISR recognizes it through the ERROR trap registers; reporting
			// the NOTIFY bit without trap state is diagnosed as a fatal GPU error.
			m_registers[PgraphTrappedAddress] = (method & 0x1FFFu) |
				((subchannel & 7u) << 16) | ((m_dmaChannel & 0x1Fu) << 20);
			m_registers[PgraphTrappedDataLow] = value;
			m_registers[PgraphNsource] = PgraphSourceNotification;
			m_registers[PgraphIntr] |= PgraphInterruptError;
			m_pgraphTrapPending = true;
			UpdateInterruptLine();
		}
		break;
	case 0x120:case NV097_FLIP_INCREMENT_WRITE:case NV097_FLIP_STALL: SubmitSurface(); break;
	default: break;
	}
}

void CxbxUwpNv2aProducer::EmitInlineVertex()
{
	Vertex v;v.attributes=m_inlineAttributes;v.position=v.attributes[0]; v.diffuse=v.attributes[3]; v.specular=v.attributes[4]; v.fog=v.attributes[4].w;
	for (unsigned i=0;i<4;i++)v.texcoord[i]=v.attributes[9+i];RunVertexProgram(v);m_inlineVertices.push_back(v);
}

void CxbxUwpNv2aProducer::RunVertexProgram(Vertex& vertex) const
{
	if(m_transformMode!=2){bool matrixPresent=false;for(unsigned i=0;i<16;i++)matrixPresent|=m_pgraphMethods[(NV097_SET_COMPOSITE_MATRIX>>2)+i]!=0;if(matrixPresent){Vec4 out={0,0,0,0};for(unsigned row=0;row<4;row++){for(unsigned col=0;col<4;col++)(&out.x)[row]+=(&vertex.position.x)[col]*AsFloat(m_pgraphMethods[(NV097_SET_COMPOSITE_MATRIX>>2)+row*4+col]);}vertex.position=out;}for(unsigned stage=0;stage<4;stage++)if(m_pgraphMethods[(NV097_SET_TEXTURE_MATRIX_ENABLE>>2)+stage]){const std::uint32_t matrixBase=(NV097_SET_TEXTURE_MATRIX>>2)+stage*16;Vec4 transformed={0,0,0,0};for(unsigned row=0;row<4;row++)for(unsigned col=0;col<4;col++)(&transformed.x)[row]+=(&vertex.texcoord[stage].x)[col]*AsFloat(m_pgraphMethods[matrixBase+row*4+col]);vertex.texcoord[stage]=transformed;}return;}
	std::array<Vec4,13> r={};std::array<Vec4,16> o={};o[0]={0,0,0,1};o[3]=o[4]=o[7]=o[8]={1,1,1,1};o[5]={1,1,1,1};for(unsigned i=9;i<=12;i++)o[i]={0,0,0,1};int a0=0;
	auto swizzle=[](const Vec4& v,unsigned s){return Vec4{(&v.x)[(s>>6)&3],(&v.x)[(s>>4)&3],(&v.x)[(s>>2)&3],(&v.x)[s&3]};};
	auto fetch=[&](unsigned mux,unsigned ri,unsigned vi,unsigned ci,unsigned sw,bool neg,bool relative){Vec4 value={0,0,0,0};if(mux==VSI_MUX_R)value=ri==12?o[0]:(ri<12?r[ri]:value);else if(mux==VSI_MUX_V)value=vertex.attributes[vi&15];else if(mux==VSI_MUX_C){int index=static_cast<int>(ci&255)+(relative?a0:0);if(index>=0&&index<static_cast<int>(m_transformConstants.size()))value=m_transformConstants[index];}value=swizzle(value,sw);if(neg){value.x=-value.x;value.y=-value.y;value.z=-value.z;value.w=-value.w;}return value;};
	auto mask=[](Vec4& dst,const Vec4& src,unsigned m){if(m&8)dst.x=src.x;if(m&4)dst.y=src.y;if(m&2)dst.z=src.z;if(m&1)dst.w=src.w;};
	auto splat=[](float f){return Vec4{f,f,f,f};};
	auto mac=[&](unsigned op,const Vec4&A,const Vec4&B,const Vec4&C){Vec4 q={};switch(op){case VSI_MAC_MOV:q=A;break;case VSI_MAC_MUL:q={A.x*B.x,A.y*B.y,A.z*B.z,A.w*B.w};break;case VSI_MAC_ADD:q={A.x+C.x,A.y+C.y,A.z+C.z,A.w+C.w};break;case VSI_MAC_MAD:q={A.x*B.x+C.x,A.y*B.y+C.y,A.z*B.z+C.z,A.w*B.w+C.w};break;case VSI_MAC_DP3:q=splat(A.x*B.x+A.y*B.y+A.z*B.z);break;case VSI_MAC_DPH:q=splat(A.x*B.x+A.y*B.y+A.z*B.z+B.w);break;case VSI_MAC_DP4:q=splat(A.x*B.x+A.y*B.y+A.z*B.z+A.w*B.w);break;case VSI_MAC_DST:q={1,A.y*B.y,A.z,B.w};break;case VSI_MAC_MIN:q={(std::min)(A.x,B.x),(std::min)(A.y,B.y),(std::min)(A.z,B.z),(std::min)(A.w,B.w)};break;case VSI_MAC_MAX:q={(std::max)(A.x,B.x),(std::max)(A.y,B.y),(std::max)(A.z,B.z),(std::max)(A.w,B.w)};break;case VSI_MAC_SLT:q={A.x<B.x?1.f:0.f,A.y<B.y?1.f:0.f,A.z<B.z?1.f:0.f,A.w<B.w?1.f:0.f};break;case VSI_MAC_SGE:q={A.x>=B.x?1.f:0.f,A.y>=B.y?1.f:0.f,A.z>=B.z?1.f:0.f,A.w>=B.w?1.f:0.f};break;}return q;};
	auto ilu=[&](unsigned op,const Vec4&C){Vec4 q={};const float x=C.x;switch(op){case VSI_ILU_MOV:q=C;break;case VSI_ILU_RCP:q=splat(x?1.f/x:std::copysign(std::numeric_limits<float>::infinity(),x));break;case VSI_ILU_RCC:q=splat((std::max)(-1.884467e19f,(std::min)(1.884467e19f,x?1.f/x:1.884467e19f)));break;case VSI_ILU_RSQ:q=splat(1.f/std::sqrt((std::max)(std::fabs(x),1e-30f)));break;case VSI_ILU_EXP:q={std::exp2(std::floor(x)),x-std::floor(x),std::exp2(x),1};break;case VSI_ILU_LOG:{float v=(std::max)(std::fabs(x),1e-30f),l=std::log2(v),f=std::floor(l);q={f,v/std::exp2(f),l,1};break;}case VSI_ILU_LIT:q={1,(std::max)(0.f,C.x),C.x>0?std::pow((std::max)(0.f,C.y),(std::max)(-128.f,(std::min)(128.f,C.w))):0,1};break;}return q;};
	for(unsigned pc=m_programStart;pc<m_transformProgram.size();pc++){const auto& inst=m_transformProgram[pc];const auto d1=inst[1],d2=inst[2],d3=inst[3];const unsigned iop=(d1>>VSI_FLD_ILU_SHIFT)&VSI_FLD_ILU_MASK,mop=(d1>>VSI_FLD_MAC_SHIFT)&VSI_FLD_MAC_MASK;const bool final=(d3>>VSI_FLD_FINAL_BIT3)&1;if(!iop&&!mop){if(final)break;continue;}const unsigned ci=(d1>>VSI_FLD_CONST_SHIFT)&VSI_FLD_CONST_MASK,vi=(d1>>VSI_FLD_V_SHIFT)&VSI_FLD_V_MASK;const bool rel=(d3>>VSI_FLD_A0X_BIT3)&1;Vec4 A=fetch((d2>>VSI_FLD_A_MUX_SHIFT)&3,(d2>>VSI_FLD_A_R_SHIFT)&15,vi,ci,d1&255,(d1>>VSI_FLD_A_NEG_BIT1)&1,rel),B=fetch((d2>>VSI_FLD_B_MUX_SHIFT)&3,(d2>>VSI_FLD_B_R_SHIFT)&15,vi,ci,(d2>>17)&255,(d2>>VSI_FLD_B_NEG_BIT2)&1,rel),C=fetch((d3>>VSI_FLD_C_MUX_SHIFT3)&3,(((d2>>VSI_FLD_C_R_HIGH_SHIFT2)&3)<<2)|((d3>>VSI_FLD_C_R_LOW_SHIFT3)&3),vi,ci,(d2>>2)&255,(d2>>VSI_FLD_C_NEG_BIT2)&1,rel);Vec4 mr={},ir={};if(mop==VSI_MAC_ARL)a0=static_cast<int>(std::floor(A.x));else if(mop)mr=mac(mop,A,B,C);if(iop)ir=ilu(iop,C);const unsigned rd=(d3>>VSI_FLD_OUT_R_SHIFT)&15,mm=(d3>>VSI_FLD_OUT_MAC_MASK_SHIFT)&15,im=(d3>>VSI_FLD_OUT_ILU_MASK_SHIFT)&15,om=(d3>>VSI_FLD_OUT_O_MASK_SHIFT)&15,oa=(d3>>VSI_FLD_OUT_ADDRESS_SHIFT)&255;const bool paired=mop&&iop;if(mop&&mop!=VSI_MAC_ARL&&mm){if(rd==12)mask(o[0],mr,mm);else if(rd<12)mask(r[rd],mr,mm);}if(iop&&im){const auto dest=paired?1:rd;if(dest==12)mask(o[0],ir,im);else if(dest<12)mask(r[dest],ir,im);}if(om&&((d3>>VSI_FLD_OUT_ORB_BIT3)&1)){const auto& result=((d3>>VSI_FLD_OUT_MUX_BIT3)&1)?ir:mr;if((oa&15)==5){if(om&8)o[5].x=result.x;else if(om&4)o[5].x=result.y;else if(om&2)o[5].x=result.z;else o[5].x=result.w;}else mask(o[oa&15],result,om);}if(final)break;}
	vertex.position=o[0];vertex.diffuse=o[3];vertex.specular=o[4];vertex.fog=o[5].x;for(unsigned i=0;i<4;i++)vertex.texcoord[i]=o[9+i];
}

bool CxbxUwpNv2aProducer::FetchVertex(std::uint32_t index, Vertex& vertex) const
{
	auto fetch=[this,index](unsigned attribute, Vec4& output)->bool {
		const auto& a=m_vertexArrays[attribute]; const auto type=a.format&15u, count=(a.format>>4)&15u, stride=a.format>>8; if(!count)return false;
		const std::uint32_t bytes=type==2?4:(type==0||type==4?1:(type==6?4:2)); const auto base=static_cast<std::uint64_t>(PhysicalAddress(a.offset))+static_cast<std::uint64_t>(index)*stride;
		for(unsigned c=0;c<count&&c<4;c++) { float f=0;
			if(type==2){std::uint32_t b;if(!ReadBytes(base+c*4,&b,4))return false;f=AsFloat(b);}
			else if(type==0||type==4){std::uint8_t b;if(!ReadBytes(base+c,&b,1))return false;f=b/255.f;}
			else if(type==1){std::int16_t b;if(!ReadBytes(base+c*2,&b,2))return false;f=static_cast<float>(b);}
			else if(type==5){std::int16_t b;if(!ReadBytes(base+c*2,&b,2))return false;f=(std::max)(-1.f,b/32767.f);}
			else if(type==6){std::uint32_t p;if(!ReadBytes(base,&p,bytes))return false;const unsigned shift=c?11u*(c<2):0u;const unsigned bits=c==2?10:11;const int raw=static_cast<int>((p>>shift)&((1u<<bits)-1));const int sign=1<<(bits-1);f=(raw&sign?raw-(1<<bits):raw)/static_cast<float>(sign-1);}
			(&output.x)[c]=f;
		} return true;
	};
	if(!fetch(0,vertex.attributes[0]))return false;for(unsigned i=1;i<16;i++)fetch(i,vertex.attributes[i]);vertex.position=vertex.attributes[0];vertex.diffuse=vertex.attributes[3];vertex.specular=vertex.attributes[4];for(unsigned i=0;i<4;i++)vertex.texcoord[i]=vertex.attributes[9+i];RunVertexProgram(vertex);return true;
}

bool CxbxUwpNv2aProducer::DecodeInlineVertices(std::vector<Vertex>& vertices) const
{
	std::uint32_t stride=0; std::array<std::uint32_t,16> offsets={};
	for(unsigned i=0;i<16;i++){offsets[i]=stride;const auto f=m_vertexArrays[i].format;const auto count=(f>>4)&15,type=f&15;stride+=count*(type==2?4:(type==0||type==4?1:2));}
	if(!stride||m_inlineArray.size()*4%stride)return false; const auto* data=reinterpret_cast<const std::uint8_t*>(m_inlineArray.data()); const auto count=static_cast<std::uint32_t>(m_inlineArray.size()*4/stride);
	vertices.resize(count);
	for(std::uint32_t i=0;i<count;i++){auto read=[&](unsigned a,Vec4& out){auto f=m_vertexArrays[a].format,n=(f>>4)&15,type=f&15;const auto* p=data+i*stride+offsets[a];for(unsigned c=0;c<n&&c<4;c++){if(type==2)std::memcpy(&(&out.x)[c],p+c*4,4);else if(type==0||type==4)(&out.x)[c]=p[c]/255.f;else{std::int16_t s;std::memcpy(&s,p+c*2,2);(&out.x)[c]=type==5?s/32767.f:static_cast<float>(s);}}};for(unsigned a=0;a<16;a++)read(a,vertices[i].attributes[a]);vertices[i].position=vertices[i].attributes[0];vertices[i].diffuse=vertices[i].attributes[3];vertices[i].specular=vertices[i].attributes[4];for(unsigned t=0;t<4;t++)vertices[i].texcoord[t]=vertices[i].attributes[9+t];RunVertexProgram(vertices[i]);}
	return true;
}

void CxbxUwpNv2aProducer::Execute2DBlit()
{
	if(m_blitOperation!=NV09F_SET_OPERATION_SRCCOPY)return;unsigned bytes=0;switch(m_surface2DFormat){case NV062_SET_COLOR_FORMAT_LE_Y8:bytes=1;break;case NV062_SET_COLOR_FORMAT_LE_R5G6B5:bytes=2;break;case NV062_SET_COLOR_FORMAT_LE_X8R8G8B8_Z8R8G8B8:case NV062_SET_COLOR_FORMAT_LE_X8R8G8B8:case NV062_SET_COLOR_FORMAT_LE_A8R8G8B8:case NV062_SET_COLOR_FORMAT_LE_Y32:bytes=4;break;default:return;}std::uint32_t sourceLimit=0,destinationLimit=0;const auto sourceBase=ResolveDmaBase(m_surface2DSourceDma,&sourceLimit)+m_surface2DSourceOffset,destinationBase=ResolveDmaBase(m_surface2DDestinationDma,&destinationLimit)+m_surface2DDestinationOffset;const unsigned inX=m_blitIn&0xFFFF,inY=m_blitIn>>16,outX=m_blitOut&0xFFFF,outY=m_blitOut>>16,width=m_blitSize&0xFFFF,height=m_blitSize>>16;if(!width||!height||!m_surface2DSourcePitch||!m_surface2DDestinationPitch)return;const auto rowBytes=static_cast<std::size_t>(width)*bytes;
	for(unsigned row=0;row<height;row++){const auto source=static_cast<std::uint64_t>(sourceBase)+(inY+row)*m_surface2DSourcePitch+inX*bytes,destination=static_cast<std::uint64_t>(destinationBase)+(outY+row)*m_surface2DDestinationPitch+outX*bytes;if(source+rowBytes>m_ramSize||destination+rowBytes>m_ramSize)break;std::memmove(m_ram+destination,m_ram+source,rowBytes);}
}

void CxbxUwpNv2aProducer::DrawArrays(std::uint32_t start, std::uint32_t count)
{
	if(!m_beginEnd||!count||count>0x100000)return;std::vector<Vertex> vertices(count);for(std::uint32_t i=0;i<count;i++)if(!FetchVertex(start+i,vertices[i]))return;DrawVertices(vertices,nullptr);
}
void CxbxUwpNv2aProducer::DrawIndexed()
{
	if(m_indices.empty())return;const auto maximum=*std::max_element(m_indices.begin(),m_indices.end());if(maximum>0x100000)return;std::vector<Vertex> vertices(maximum+1);for(std::uint32_t i=0;i<=maximum;i++)if(!FetchVertex(i,vertices[i]))return;DrawVertices(vertices,&m_indices);
}

void CxbxUwpNv2aProducer::DrawVertices(const std::vector<Vertex>& vertices,const std::vector<std::uint32_t>* indexData)
{
	std::vector<std::uint32_t> sequential;if(!indexData){sequential.resize(vertices.size());for(std::uint32_t i=0;i<sequential.size();i++)sequential[i]=i;indexData=&sequential;}const auto& idx=*indexData;
	auto V=[&](std::size_t i)->const Vertex&{return vertices[idx[i]];};auto tri=[&](std::size_t a,std::size_t b,std::size_t c){if(idx[a]<vertices.size()&&idx[b]<vertices.size()&&idx[c]<vertices.size())RasterizeTriangle(V(a),V(b),V(c));};
	switch(m_beginEnd){
	case 1:for(std::size_t i=0;i<idx.size();i++)if(idx[i]<vertices.size())RasterizePoint(V(i));break;
	case 2:for(std::size_t i=0;i+1<idx.size();i+=2)RasterizeLine(V(i),V(i+1));break;
	case 3:for(std::size_t i=1;i<idx.size();i++)RasterizeLine(V(i-1),V(i));if(idx.size()>2)RasterizeLine(V(idx.size()-1),V(0));break;
	case 4:for(std::size_t i=1;i<idx.size();i++)RasterizeLine(V(i-1),V(i));break;
	case 5:for(std::size_t i=0;i+2<idx.size();i+=3)tri(i,i+1,i+2);break;
	case 6:for(std::size_t i=2;i<idx.size();i++)(i&1)?tri(i-1,i-2,i):tri(i-2,i-1,i);break;
	case 7:case 10:for(std::size_t i=2;i<idx.size();i++)tri(0,i-1,i);break;
	case 8:for(std::size_t i=0;i+3<idx.size();i+=4){tri(i,i+1,i+2);tri(i,i+2,i+3);}break;
	case 9:for(std::size_t i=3;i<idx.size();i+=2){tri(i-3,i-2,i);tri(i-3,i,i-1);}break;
	}
}

static void ToScreen(const CxbxUwpNv2aProducer::Vertex& v,std::uint32_t width,std::uint32_t height,const std::array<float,4>& scale,const std::array<float,4>& offset,float& x,float& y,float& z)
{
	const float rw=std::fabs(v.position.w)>1e-20f?1.f/v.position.w:1.f;const float nx=v.position.x*rw,ny=v.position.y*rw,nz=v.position.z*rw;
	const bool viewport=std::fabs(scale[0])>1.1f||std::fabs(scale[1])>1.1f;x=viewport?nx*scale[0]+offset[0]:(nx*.5f+.5f)*(width-1);y=viewport?ny*scale[1]+offset[1]:(1.f-(ny*.5f+.5f))*(height-1);z=Clamp(viewport?nz*scale[2]+offset[2]:nz);
}

void CxbxUwpNv2aProducer::RasterizePoint(const Vertex& a)
{
	float x,y,z;ToScreen(a,m_width,m_height,m_viewportScale,m_viewportOffset,x,y,z);const int radius=(std::max)(0,static_cast<int>(m_pointSize/8)/2);for(int py=static_cast<int>(y)-radius;py<=static_cast<int>(y)+radius;py++)for(int px=static_cast<int>(x)-radius;px<=static_cast<int>(x)+radius;px++)if(px>=0&&py>=0&&px<static_cast<int>(m_width)&&py<static_cast<int>(m_height)){auto c=ShadePixel(a);if(FragmentTests(px,py,z,c))WritePixel(px,py,c);}
}
void CxbxUwpNv2aProducer::RasterizeLine(const Vertex& a,const Vertex& b)
{
	float ax,ay,az,bx,by,bz;ToScreen(a,m_width,m_height,m_viewportScale,m_viewportOffset,ax,ay,az);ToScreen(b,m_width,m_height,m_viewportScale,m_viewportOffset,bx,by,bz);const int steps=(std::max)(1,static_cast<int>((std::max)(std::fabs(bx-ax),std::fabs(by-ay))));
	for(int i=0;i<=steps;i++){float t=i/static_cast<float>(steps);int x=static_cast<int>(ax+(bx-ax)*t),y=static_cast<int>(ay+(by-ay)*t);Vertex v=a;auto mix=[t](float p,float q){return p+(q-p)*t;};for(int c=0;c<4;c++){(&v.diffuse.x)[c]=mix((&a.diffuse.x)[c],(&b.diffuse.x)[c]);for(int s=0;s<4;s++)(&v.texcoord[s].x)[c]=mix((&a.texcoord[s].x)[c],(&b.texcoord[s].x)[c]);}const int radius=(std::max)(0,static_cast<int>(m_lineWidth/8)/2);for(int oy=-radius;oy<=radius;oy++)for(int ox=-radius;ox<=radius;ox++){const int px=x+ox,py=y+oy;if(px<0||py<0||px>=static_cast<int>(m_width)||py>=static_cast<int>(m_height))continue;auto color=ShadePixel(v);if(FragmentTests(px,py,mix(az,bz),color))WritePixel(px,py,color);}}
}

void CxbxUwpNv2aProducer::RasterizeTriangle(const Vertex& a,const Vertex& b,const Vertex& c)
{
	if(!m_colorPitch||!m_width||!m_height)return;float ax,ay,az,bx,by,bz,cx,cy,cz;ToScreen(a,m_width,m_height,m_viewportScale,m_viewportOffset,ax,ay,az);ToScreen(b,m_width,m_height,m_viewportScale,m_viewportOffset,bx,by,bz);ToScreen(c,m_width,m_height,m_viewportScale,m_viewportOffset,cx,cy,cz);const float area=Edge(ax,ay,bx,by,cx,cy);if(std::fabs(area)<1e-8f)return;
	if(m_cull){const bool front=m_frontFace==0x0900u?area<0:area>0;if(m_cullFace==0x0408u||(m_cullFace==0x0404u&&front)||(m_cullFace==0x0405u&&!front))return;}
	const bool front=m_frontFace==0x0900u?area<0:area>0;const auto polygonMode=front?m_frontPolygonMode:m_backPolygonMode;if(polygonMode==0x1B00u){RasterizePoint(a);RasterizePoint(b);RasterizePoint(c);return;}if(polygonMode==0x1B01u){RasterizeLine(a,b);RasterizeLine(b,c);RasterizeLine(c,a);return;}
	const int minX=(std::max)(static_cast<int>(m_clipX),static_cast<int>(std::floor((std::min)({ax,bx,cx}))));const int maxX=(std::min)(static_cast<int>(m_clipX+m_width)-1,static_cast<int>(std::ceil((std::max)({ax,bx,cx}))));const int minY=(std::max)(static_cast<int>(m_clipY),static_cast<int>(std::floor((std::min)({ay,by,cy}))));const int maxY=(std::min)(static_cast<int>(m_clipY+m_height)-1,static_cast<int>(std::ceil((std::max)({ay,by,cy}))));
	for(int y=minY;y<=maxY;y++)for(int x=minX;x<=maxX;x++){float w0=Edge(bx,by,cx,cy,x+.5f,y+.5f)/area,w1=Edge(cx,cy,ax,ay,x+.5f,y+.5f)/area,w2=1-w0-w1;if(w0<0||w1<0||w2<0)continue;Vertex v;for(int k=0;k<4;k++){(&v.diffuse.x)[k]=m_shadeMode==0x1D00u?(&c.diffuse.x)[k]:w0*(&a.diffuse.x)[k]+w1*(&b.diffuse.x)[k]+w2*(&c.diffuse.x)[k];(&v.specular.x)[k]=w0*(&a.specular.x)[k]+w1*(&b.specular.x)[k]+w2*(&c.specular.x)[k];for(int s=0;s<4;s++)(&v.texcoord[s].x)[k]=w0*(&a.texcoord[s].x)[k]+w1*(&b.texcoord[s].x)[k]+w2*(&c.texcoord[s].x)[k];}v.fog=w0*a.fog+w1*b.fog+w2*c.fog;auto color=ShadePixel(v);if(FragmentTests(x,y,w0*az+w1*bz+w2*cz,color))WritePixel(x,y,color);}
}

CxbxUwpNv2aProducer::ColorF CxbxUwpNv2aProducer::SampleTexture(std::uint32_t stage,const Vec4& coordinate,bool applyFilter) const
{
	if(stage>=4)return {1,1,1,1};const auto&t=m_textures[stage];if(!(t.control0&(1u<<30)))return {1,1,1,1};float u=coordinate.x,v=coordinate.y;const float q=coordinate.w;if(std::fabs(q)>1e-20f){u/=q;v/=q;}const auto format=(t.format>>8)&255u;std::uint32_t width=t.rect>>16,height=t.rect&0xFFFF;if(!width)width=1u<<((t.format>>20)&15);if(!height)height=1u<<((t.format>>24)&15);if(!width||!height)return {1,1,1,1};std::uint64_t textureBase=PhysicalAddress(t.offset);
	if(t.format&4u){const float rx=coordinate.x,ry=coordinate.y,rz=coordinate.z,ax=std::fabs(rx),ay=std::fabs(ry),az=std::fabs(rz);unsigned face=0;float sc=0,tc=0,ma=1;if(ax>=ay&&ax>=az){ma=ax;face=rx>=0?0:1;sc=rx>=0?-rz:rz;tc=-ry;}else if(ay>=az){ma=ay;face=ry>=0?2:3;sc=rx;tc=ry>=0?rz:-rz;}else{ma=az;face=rz>=0?4:5;sc=rz>=0?rx:-rx;tc=-ry;}u=.5f*(sc/ma+1);v=.5f*(tc/ma+1);unsigned faceBytes=(format==0x0C)?((width+3)/4)*((height+3)/4)*8:((format==0x0E||format==0x0F)?((width+3)/4)*((height+3)/4)*16:width*height*((format==0||format==1||format==0x0B||format==0x13||format==0x19||format==0x1F)?1:((format>=2&&format<=5)||format==0x10||format==0x11||format==0x1C||format==0x1D||format==0x24||format==0x25?2:4)));textureBase+=static_cast<std::uint64_t>(face)*faceBytes;}
	if(applyFilter&&!(t.format&4u)&&(((t.filter>>24)&15u)>1u||((t.filter>>16)&255u)>1u)){const float sx=u*width-.5f,sy=v*height-.5f,fx=sx-std::floor(sx),fy=sy-std::floor(sy);Vec4 c00=coordinate,c10=coordinate,c01=coordinate,c11=coordinate;c00.x=(std::floor(sx)+.5f)/width;c00.y=(std::floor(sy)+.5f)/height;c00.w=1;c10=c00;c10.x+=1.f/width;c01=c00;c01.y+=1.f/height;c11=c10;c11.y+=1.f/height;const auto a=SampleTexture(stage,c00,false),b=SampleTexture(stage,c10,false),c=SampleTexture(stage,c01,false),d=SampleTexture(stage,c11,false);ColorF result;for(int component=0;component<4;component++){const float top=(&a.r)[component]+((&b.r)[component]-(&a.r)[component])*fx,bottom=(&c.r)[component]+((&d.r)[component]-(&c.r)[component])*fx;(&result.r)[component]=top+(bottom-top)*fy;}return result;}
	auto coord=[](float x,std::uint32_t n,std::uint32_t mode){if(mode==3)return (std::min)(n-1,static_cast<std::uint32_t>(Clamp(x)*(n-1)));float f=x*n;if(mode==2)f=std::fabs(std::fmod(f,2.f)-1.f);else f-=std::floor(f);return (std::min)(n-1,static_cast<std::uint32_t>(f*n));};const auto x=coord(u,width,t.address&15),y=coord(v,height,(t.address>>8)&15);
	const bool linear=format>=0x10&&format<=0x41;std::uint32_t pitch=(t.control1>>16)&0xFFFF,argb=0xFFFFFFFF;auto read16=[&](std::uint64_t a){std::uint16_t z=0;ReadBytes(a,&z,2);return z;};auto decode16=[](std::uint16_t z,int kind)->std::uint32_t{if(kind==5)return 0xFF000000u|(((z>>11)&31)*255/31<<16)|(((z>>5)&63)*255/63<<8)|(z&31)*255/31;return static_cast<std::uint32_t>(((kind==4?(z>>12)*17:255)<<24)|(((z>>10)&31)*255/31<<16)|(((z>>5)&31)*255/31<<8)|(z&31)*255/31);};
	if(format==0x0C||format==0x0E||format==0x0F){const auto block=textureBase+(y/4)*((width+3)/4)*(format==0x0C?8:16)+(x/4)*(format==0x0C?8:16);std::uint8_t d[16]={};if(!ReadBytes(block,d,format==0x0C?8:16))return {1,1,1,1};const int colorBase=format==0x0C?0:8;std::uint16_t c0,c1;std::memcpy(&c0,d+colorBase,2);std::memcpy(&c1,d+colorBase+2,2);std::uint32_t colors[4]={decode16(c0,5),decode16(c1,5),0,0};auto mix=[](std::uint32_t p,std::uint32_t q,int a,int b){return 0xFF000000u|((((p>>16&255)*a+(q>>16&255)*b)/(a+b))<<16)|((((p>>8&255)*a+(q>>8&255)*b)/(a+b))<<8)|(((p&255)*a+(q&255)*b)/(a+b));};colors[2]=mix(colors[0],colors[1],2,1);colors[3]=c0>c1?mix(colors[0],colors[1],1,2):0;std::uint32_t bits;std::memcpy(&bits,d+colorBase+4,4);argb=colors[(bits>>(2*((y&3)*4+(x&3))))&3];if(format!=0x0C){std::uint8_t alpha=255;const auto pixel=(y&3)*4+(x&3);if(format==0x0E)alpha=((d[pixel/2]>>(4*(pixel&1)))&15)*17;else{const auto a0=d[0],a1=d[1];std::uint64_t ab=0;std::memcpy(&ab,d+2,6);const auto ai=(ab>>(pixel*3))&7;if(ai==0)alpha=a0;else if(ai==1)alpha=a1;else alpha=a0>a1?static_cast<std::uint8_t>(((8-ai)*a0+(ai-1)*a1)/7):static_cast<std::uint8_t>(ai<6?((6-ai)*a0+(ai-1)*a1)/5:(ai==6?0:255));}argb=(argb&0xFFFFFF)|(alpha<<24);} }
	else {unsigned bytes=(format==0||format==1||format==0x0B||format==0x13||format==0x19||format==0x1F)?1:((format>=2&&format<=5)||format==0x10||format==0x11||format==0x1C||format==0x1D||format==0x24||format==0x25?2:4);if(!pitch)pitch=width*bytes;const auto texel=textureBase+(linear?(static_cast<std::uint64_t>(y)*pitch+x*bytes):static_cast<std::uint64_t>(Morton2(x,y))*bytes);if(format==0x24||format==0x25){std::uint8_t pair[4]={};const auto pairAddress=textureBase+static_cast<std::uint64_t>(y)*pitch+(x&~1u)*2;ReadBytes(pairAddress,pair,4);int yy=pair[(x&1)?2:0],u=(format==0x24?pair[0]:pair[1])-128,vv=(format==0x24?pair[2]:pair[3])-128;if(format==0x24)yy=pair[(x&1)?3:1];const int c=yy-16;auto cb=[](int n){return static_cast<std::uint32_t>((std::max)(0,(std::min)(255,n)));};argb=0xFF000000u|(cb((298*c+409*vv+128)>>8)<<16)|(cb((298*c-100*u-208*vv+128)>>8)<<8)|cb((298*c+516*u+128)>>8);}else if(bytes==4)ReadBytes(texel,&argb,4);else if(bytes==2)argb=decode16(read16(texel),format==5||format==0x11?5:(format==4||format==0x1D?4:2));else{std::uint8_t b=0;ReadBytes(texel,&b,1);if(format==0x19||format==0x1F)argb=static_cast<std::uint32_t>(b)<<24|0xFFFFFF;else if(format==0x0B){std::uint32_t p=0;ReadBytes(PhysicalAddress(t.palette&0xFFFFFFC0u)+b*4,&p,4);argb=p;}else argb=0xFF000000u|b*0x010101u;}}
	return Unpack(argb);
}

CxbxUwpNv2aProducer::ColorF CxbxUwpNv2aProducer::ApplyRegisterCombiners(const Vertex& vertex,const std::array<ColorF,4>& tex) const
{
	std::array<ColorF,16> reg={};reg[0]={0,0,0,0};reg[3]={vertex.fog,vertex.fog,vertex.fog,vertex.fog};reg[4]={vertex.diffuse.x,vertex.diffuse.y,vertex.diffuse.z,vertex.diffuse.w};reg[5]={vertex.specular.x,vertex.specular.y,vertex.specular.z,vertex.specular.w};for(unsigned i=0;i<4;i++)reg[8+i]=tex[i];
	const unsigned stages=(std::min)(8u,m_combinerControl&255u);if(!stages){ColorF out=reg[4];for(unsigned i=0;i<4;i++)if(m_textures[i].control0&(1u<<30)){out.r*=tex[i].r;out.g*=tex[i].g;out.b*=tex[i].b;out.a*=tex[i].a;}return out;}
	auto method=[this](std::uint32_t offset){return m_pgraphMethods[offset>>2];};
	auto mapped=[](float v,unsigned map){switch(map){case 1:return 1-v;case 2:return 2*v-1;case 3:return 1-2*v;case 4:return v-.5f;case 5:return .5f-v;case 6:return v;case 7:return -v;default:return v;}};
	auto input=[&](std::uint8_t descriptor)->ColorF{auto value=reg[descriptor&15];if(descriptor&16)value.r=value.g=value.b=value.a;const unsigned map=descriptor>>5;value.r=mapped(value.r,map);value.g=mapped(value.g,map);value.b=mapped(value.b,map);value.a=mapped(value.a,map);return value;};
	auto scale=[](ColorF value,unsigned op){float multiplier=1,bias=0;if(op==1)bias=-.5f;else if(op==2)multiplier=2;else if(op==3){multiplier=2;bias=-.5f;}else if(op==4)multiplier=4;else if(op==6)multiplier=.5f;value.r=value.r*multiplier+bias;value.g=value.g*multiplier+bias;value.b=value.b*multiplier+bias;value.a=value.a*multiplier+bias;return value;};
	for(unsigned stage=0;stage<stages;stage++){
		reg[1]=Unpack(method(NV097_SET_COMBINER_FACTOR0+stage*4));reg[2]=Unpack(method(NV097_SET_COMBINER_FACTOR1+stage*4));
		const auto ci=method(NV097_SET_COMBINER_COLOR_ICW+stage*4),co=method(NV097_SET_COMBINER_COLOR_OCW+stage*4),ai=method(NV097_SET_COMBINER_ALPHA_ICW+stage*4),ao=method(NV097_SET_COMBINER_ALPHA_OCW+stage*4);
		auto A=input(ci>>24),B=input(ci>>16),C=input(ci>>8),D=input(ci);ColorF ab,cd;const bool dotAB=co&(1u<<13),dotCD=co&(1u<<12);if(dotAB){ab.r=ab.g=ab.b=A.r*B.r+A.g*B.g+A.b*B.b;}else{ab={A.r*B.r,A.g*B.g,A.b*B.b,A.a*B.a};}if(dotCD){cd.r=cd.g=cd.b=C.r*D.r+C.g*D.g+C.b*D.b;}else{cd={C.r*D.r,C.g*D.g,C.b*D.b,C.a*D.a};}ColorF sum={ab.r+cd.r,ab.g+cd.g,ab.b+cd.b,ab.a+cd.a};ab=scale(ab,(co>>15)&7);cd=scale(cd,(co>>15)&7);sum=scale(sum,(co>>15)&7);const unsigned abDst=(co>>4)&15,cdDst=co&15,sumDst=(co>>8)&15;if(abDst)reg[abDst]=ab;if(cdDst)reg[cdDst]=cd;if(sumDst)reg[sumDst]=(co&(1u<<14))?((reg[12].a>=.5f)?cd:ab):sum;
		auto aA=input(ai>>24),aB=input(ai>>16),aC=input(ai>>8),aD=input(ai);float alphaAB=aA.a*aB.a,alphaCD=aC.a*aD.a,alphaSum=alphaAB+alphaCD;const unsigned alphaOp=(ao>>15)&7;ColorF ta={alphaAB,alphaAB,alphaAB,alphaAB},tc={alphaCD,alphaCD,alphaCD,alphaCD},ts={alphaSum,alphaSum,alphaSum,alphaSum};ta=scale(ta,alphaOp);tc=scale(tc,alphaOp);ts=scale(ts,alphaOp);const unsigned aAbDst=(ao>>4)&15,aCdDst=ao&15,aSumDst=(ao>>8)&15;if(aAbDst)reg[aAbDst].a=ta.a;if(aCdDst)reg[aCdDst].a=tc.a;if(aSumDst)reg[aSumDst].a=(ao&(1u<<14))?((reg[12].a>=.5f)?tc.a:ta.a):ts.a;reg[14]={reg[12].r+reg[13].r,reg[12].g+reg[13].g,reg[12].b+reg[13].b,reg[12].a};reg[15]={A.r*C.r,A.g*C.g,A.b*C.b,A.a*C.a};
	}
	ColorF out=reg[12];out.r=Clamp(out.r+reg[5].r);out.g=Clamp(out.g+reg[5].g);out.b=Clamp(out.b+reg[5].b);out.a=Clamp(out.a);return out;
}

CxbxUwpNv2aProducer::ColorF CxbxUwpNv2aProducer::ShadePixel(const Vertex& vertex) const
{
	if (!m_pixelShadersEnabled) return { vertex.diffuse.x, vertex.diffuse.y, vertex.diffuse.z, vertex.diffuse.w };
	std::array<ColorF,4> texture={};std::array<Vec4,4> coordinate=vertex.texcoord;for(unsigned stage=0;stage<4;stage++){const auto program=(m_shaderStageProgram>>(stage*5))&31u;if(stage&&program>=0x0F){const auto inputStage=stage==1?(m_shaderOtherStageInput&15):((m_shaderOtherStageInput>>(stage==2?16:20))&15);const auto& dependency=texture[(std::min)(inputStage,stage-1)];if(program==0x0F)coordinate[stage]={dependency.a,dependency.r,0,1};else if(program==0x10)coordinate[stage]={dependency.g,dependency.b,0,1};else if(program==0x11){const float dot=dependency.r*coordinate[stage].x+dependency.g*coordinate[stage].y+dependency.b*coordinate[stage].z;coordinate[stage]={dot,dot,dot,1};}}texture[stage]=program?SampleTexture(stage,coordinate[stage]):ColorF{1,1,1,1};}auto output=ApplyRegisterCombiners(vertex,texture);if(m_fogEnabled){const float fogValue=(m_fogMode==0x800u||m_fogMode==0x802u)?std::exp2(-std::fabs(vertex.fog)*m_fogParams[1]):((m_fogMode==0x801u||m_fogMode==0x803u)?std::exp2(-std::pow(std::fabs(vertex.fog)*m_fogParams[1],2.f)):vertex.fog*m_fogParams[0]+m_fogParams[1]);const auto fog=Unpack(m_fogColor);const float f=Clamp(fogValue);output.r=f*output.r+(1-f)*fog.r;output.g=f*output.g+(1-f)*fog.g;output.b=f*output.b+(1-f)*fog.b;}return output;
}

CxbxUwpNv2aProducer::ColorF CxbxUwpNv2aProducer::ReadPixel(std::uint32_t x,std::uint32_t y) const
{
	const auto colorFormat=m_surfaceFormat&15u;const bool sixteen=colorFormat<=3,swizzled=((m_surfaceFormat>>8)&15u)==2;const auto address=static_cast<std::uint64_t>(m_colorOffset)+(swizzled?static_cast<std::uint64_t>(Morton2(x,y))*(sixteen?2:4):static_cast<std::uint64_t>(y)*m_colorPitch+x*(sixteen?2:4));if(sixteen){std::uint16_t p=0;if(!ReadBytes(address,&p,2))return {};if(colorFormat==3)return Unpack(0xFF000000u|(((p>>11)&31)*255/31<<16)|(((p>>5)&63)*255/63<<8)|(p&31)*255/31);return Unpack(0xFF000000u|(((p>>10)&31)*255/31<<16)|(((p>>5)&31)*255/31<<8)|(p&31)*255/31);}std::uint32_t p=0;if(!ReadBytes(address,&p,4))return {};return Unpack(p);
}

bool CxbxUwpNv2aProducer::FragmentTests(std::uint32_t x,std::uint32_t y,float z,ColorF& source)
{
	if(m_alphaTest&&!Compare(m_alphaFunc,source.a,(m_alphaRef&255)/255.f))return false;const bool z24=((m_surfaceFormat>>4)&15u)==2,swizzled=((m_surfaceFormat>>8)&15u)==2;const auto zaddr=static_cast<std::uint64_t>(m_zetaOffset)+(swizzled?static_cast<std::uint64_t>(Morton2(x,y))*(z24?4:2):static_cast<std::uint64_t>(y)*m_zetaPitch+x*(z24?4:2));std::uint32_t packed=0;if(z24)ReadBytes(zaddr,&packed,4);else{std::uint16_t p=0;ReadBytes(zaddr,&p,2);packed=p;}float oldz=z24?(packed>>8)/16777215.f:(packed&65535)/65535.f;std::uint32_t stencil=z24?packed&255:0;
	auto writeStencil=[&](std::uint32_t op){if(!z24)return;auto next=ApplyStencilOp(op,stencil,m_stencilRef)&255;next=(stencil&~m_stencilWriteMask)|(next&m_stencilWriteMask);packed=(packed&0xFFFFFF00u)|next;std::memcpy(m_ram+zaddr,&packed,4);};
	if(m_stencilTest&&!Compare(m_stencilFunc,static_cast<float>(stencil&m_stencilFuncMask),static_cast<float>(m_stencilRef&m_stencilFuncMask))){writeStencil(m_stencilFail);return false;}if(m_depthTest&&!Compare(m_depthFunc,z,oldz)){if(m_stencilTest)writeStencil(m_stencilZFail);return false;}if(m_stencilTest)writeStencil(m_stencilZPass);if(m_depthWrite&&(m_zetaPitch||swizzled)&&zaddr+(z24?4:2)<=m_ramSize){if(z24){packed=(static_cast<std::uint32_t>(Clamp(z)*16777215.f)<<8)|(packed&255);std::memcpy(m_ram+zaddr,&packed,4);}else{std::uint16_t p=static_cast<std::uint16_t>(Clamp(z)*65535.f);std::memcpy(m_ram+zaddr,&p,2);}}if(m_zpassCountEnabled&&m_zpassCount!=0xFFFFFFFFu)++m_zpassCount;return true;
}

void CxbxUwpNv2aProducer::WritePixel(std::uint32_t x,std::uint32_t y,const ColorF& input)
{
	ColorF source=input,destination=ReadPixel(x,y);if(m_blend){const auto constant=Unpack(m_blendColor);auto factor=[&](std::uint32_t f,int c,bool src){float s=(&source.r)[c],d=(&destination.r)[c],sa=source.a,da=destination.a,k=(&constant.r)[c];switch(f){case 0:return 0.f;case 1:return 1.f;case 0x300:return src?s:d;case 0x301:return 1-(src?s:d);case 0x302:return sa;case 0x303:return 1-sa;case 0x304:return da;case 0x305:return 1-da;case 0x306:return src?d:s;case 0x307:return 1-(src?d:s);case 0x308:return (std::min)(sa,1-da);case 0x8001:return k;case 0x8002:return 1-k;case 0x8003:return constant.a;case 0x8004:return 1-constant.a;default:return 1.f;}};for(int c=0;c<4;c++){float s=(&source.r)[c]*factor(m_blendSrc,c,true),d=(&destination.r)[c]*factor(m_blendDst,c,false),v=m_blendEquation==0x800A?s-d:(m_blendEquation==0x800B?d-s:(m_blendEquation==0x8007?(std::min)(s,d):(m_blendEquation==0x8008?(std::max)(s,d):s+d)));(&source.r)[c]=Clamp(v);}}
	if(m_logicOpEnabled){std::uint32_t s=Byte(source.a)<<24|Byte(source.r)<<16|Byte(source.g)<<8|Byte(source.b),d=Byte(destination.a)<<24|Byte(destination.r)<<16|Byte(destination.g)<<8|Byte(destination.b),q=s;switch(m_logicOp){case 0x1500:q=0;break;case 0x1501:q=s&d;break;case 0x1502:q=s&~d;break;case 0x1503:break;case 0x1504:q=~s&d;break;case 0x1505:q=d;break;case 0x1506:q=s^d;break;case 0x1507:q=s|d;break;case 0x1508:q=~(s|d);break;case 0x1509:q=~(s^d);break;case 0x150A:q=~d;break;case 0x150B:q=s|~d;break;case 0x150C:q=~s;break;case 0x150D:q=~s|d;break;case 0x150E:q=~(s&d);break;case 0x150F:q=0xFFFFFFFFu;break;}source=Unpack(q);}
	if(!(m_colorMask&0x000000FF))source.b=destination.b;if(!(m_colorMask&0x0000FF00))source.g=destination.g;if(!(m_colorMask&0x00FF0000))source.r=destination.r;if(!(m_colorMask&0xFF000000))source.a=destination.a;const std::uint32_t argb=Byte(source.a)<<24|Byte(source.r)<<16|Byte(source.g)<<8|Byte(source.b);const auto colorFormat=m_surfaceFormat&15u;const bool sixteen=colorFormat<=3,swizzled=((m_surfaceFormat>>8)&15u)==2;const auto address=static_cast<std::uint64_t>(m_colorOffset)+(swizzled?static_cast<std::uint64_t>(Morton2(x,y))*(sixteen?2:4):static_cast<std::uint64_t>(y)*m_colorPitch+x*(sixteen?2:4));if(address+(sixteen?2:4)>m_ramSize)return;if(!sixteen)std::memcpy(m_ram+address,&argb,4);else{std::uint16_t p=colorFormat==3?static_cast<std::uint16_t>(((argb>>19)&31)<<11|((argb>>10)&63)<<5|((argb>>3)&31)):static_cast<std::uint16_t>(((argb>>19)&31)<<10|((argb>>11)&31)<<5|((argb>>3)&31));std::memcpy(m_ram+address,&p,2);}
}

void CxbxUwpNv2aProducer::ClearSurface(std::uint32_t flags)
{
	if(!m_width||!m_height)return;const unsigned left=m_clearRectHorizontal&0xFFFF,right=(std::min)(m_width-1,m_clearRectHorizontal>>16),top=m_clearRectVertical&0xFFFF,bottom=(std::min)(m_height-1,m_clearRectVertical>>16);const auto clear=Unpack(m_colorClearValue);const bool swizzled=((m_surfaceFormat>>8)&15)==2;for(unsigned y=top;y<=bottom&&y<m_height;y++)for(unsigned x=left;x<=right&&x<m_width;x++){if(flags&0xF0)WritePixel(x,y,clear);if((flags&3)&&(m_zetaPitch||swizzled)){const bool z24=((m_surfaceFormat>>4)&15)==2;const auto a=static_cast<std::uint64_t>(m_zetaOffset)+(swizzled?static_cast<std::uint64_t>(Morton2(x,y))*(z24?4:2):static_cast<std::uint64_t>(y)*m_zetaPitch+x*(z24?4:2));if(a+(z24?4:2)>m_ramSize)continue;if(z24){std::uint32_t old=0;std::memcpy(&old,m_ram+a,4);std::uint32_t v=((flags&1)?m_zstencilClearValue&0xFFFFFF00:old&0xFFFFFF00)|((flags&2)?m_zstencilClearValue&255:old&255);std::memcpy(m_ram+a,&v,4);}else if(flags&1){std::uint16_t v=static_cast<std::uint16_t>(m_zstencilClearValue);std::memcpy(m_ram+a,&v,2);}}}SubmitSurface();
}

void CxbxUwpNv2aProducer::CompositeOverlay(std::vector<std::uint32_t>& frame) const
{
	auto reg=[this](std::uint32_t offset){auto i=m_registers.find(offset);return i==m_registers.end()?0u:i->second;};
	const auto enabled=reg(PvideoBuffer);if(!enabled||frame.size()!=static_cast<std::size_t>(m_width)*m_height)return;const unsigned buffer=(enabled&1)?0:1;
	const auto base=reg(0x008900u+buffer*4),offset=reg(0x008920u+buffer*4),sizeIn=reg(0x008928u+buffer*4),pointOut=reg(0x008948u+buffer*4),sizeOut=reg(0x008950u+buffer*4),format=reg(0x008958u+buffer*4);
	const unsigned srcW=sizeIn&0x7FF,srcH=(sizeIn>>16)&0x7FF,pitch=format&0x1FFF,dstX=pointOut&0xFFF,dstY=(pointOut>>16)&0xFFF,dstW=sizeOut&0xFFF,dstH=(sizeOut>>16)&0xFFF;if(!srcW||!srcH||pitch<srcW*2||!dstW||!dstH)return;const auto source=static_cast<std::uint64_t>(PhysicalAddress(base+offset));if(source+static_cast<std::uint64_t>(pitch)*srcH>m_ramSize)return;
	auto clampByte=[](int value){return static_cast<std::uint32_t>((std::max)(0,(std::min)(255,value)));};
	for(unsigned oy=0;oy<dstH&&dstY+oy<m_height;oy++){const unsigned sy=static_cast<unsigned>(static_cast<std::uint64_t>(oy)*srcH/dstH);for(unsigned ox=0;ox<dstW&&dstX+ox<m_width;ox++){const unsigned sx=static_cast<unsigned>(static_cast<std::uint64_t>(ox)*srcW/dstW);const auto pair=m_ram+source+static_cast<std::uint64_t>(sy)*pitch+(sx&~1u)*2;const int y=pair[(sx&1)?2:0],u=pair[1]-128,v=pair[3]-128,c=y-16;const auto r=clampByte((298*c+409*v+128)>>8),g=clampByte((298*c-100*u-208*v+128)>>8),b=clampByte((298*c+516*u+128)>>8);auto& pixel=frame[static_cast<std::size_t>(dstY+oy)*m_width+dstX+ox];if(format&(1u<<20)){const auto key=reg(0x008B00u+buffer*4)&0xFFFFFF;if((pixel&0xFFFFFF)!=key)continue;}pixel=0xFF000000u|(r<<16)|(g<<8)|b;}}
}

void CxbxUwpNv2aProducer::SubmitSurface()
{
	if (!m_width || !m_height || m_colorOffset >= m_ramSize) return;
	const auto colorFormat = m_surfaceFormat & 15u;
	const bool rgb565 = colorFormat == 3;
	const bool sixteen = colorFormat <= 3;
	const bool swizzled = ((m_surfaceFormat >> 8) & 15u) == 2;
	const unsigned bytes = sixteen ? 2 : 4;
	if ((!swizzled && (m_colorPitch < m_width * bytes ||
		static_cast<std::uint64_t>(m_colorOffset) + static_cast<std::uint64_t>(m_colorPitch) * m_height > m_ramSize)) ||
		(swizzled && static_cast<std::uint64_t>(m_colorOffset) +
			static_cast<std::uint64_t>(m_width) * m_height * bytes > m_ramSize)) return;
	auto submit = [this](const void* pixels, UINT pitch, CxbxUwpGuestPixelFormat format) {
		const HRESULT result = CxbxUwpSubmitGuestFrame(pixels, m_width, m_height, pitch, format);
		if (SUCCEEDED(result) && !m_loggedFirstFrame && m_logger) {
			char line[176] = {};
			sprintf_s(line, "[uwp-nv2a] Primeiro framebuffer entregue ao D3D11: %ux%u pitch=%u offset=%08X.\r\n",
				m_width, m_height, pitch, m_colorOffset);
			m_logger(line);
			m_loggedFirstFrame = true;
		}
		return result;
	};
	const auto overlay = m_registers.find(PvideoBuffer);
	const bool hasOverlay = overlay != m_registers.end() && overlay->second != 0;
	if (!swizzled && !hasOverlay && (rgb565 || !sixteen)) {
		submit(m_ram + m_colorOffset, m_colorPitch,
			rgb565 ? CxbxUwpGuestPixelFormat::Rgb565 : CxbxUwpGuestPixelFormat::Bgra8);
		return;
	}
	std::vector<std::uint32_t> converted(static_cast<std::size_t>(m_width) * m_height);
	for (unsigned y = 0; y < m_height; ++y) for (unsigned x = 0; x < m_width; ++x) {
		auto color = ReadPixel(x, y);
		converted[static_cast<std::size_t>(y) * m_width + x] =
			0xFF000000u | Byte(color.r) << 16 | Byte(color.g) << 8 | Byte(color.b);
	}
	if (hasOverlay) CompositeOverlay(converted);
	submit(converted.data(), m_width * 4, CxbxUwpGuestPixelFormat::Bgra8);
}

bool CxbxUwpNv2aProducer::HasEnabledInterrupt() const
{
	if ((Register(PmcIntrEnable) & 1u) == 0) return false;
	return (Register(PfifoIntr) & Register(PfifoIntrEnable)) != 0 ||
		(Register(PgraphIntr) & Register(PgraphIntrEnable)) != 0 ||
		(Register(PcrtcIntr) & Register(PcrtcIntrEnable)) != 0;
}

std::uint32_t CxbxUwpNv2aProducer::Register(std::uint32_t offset) const
{
	auto found = m_registers.find(offset);
	if (found != m_registers.end()) return found->second;
	if (offset >= PraminOffset && offset - PraminOffset < PraminPhysicalSize) {
		const std::uint64_t physical = static_cast<std::uint64_t>(PraminPhysicalBase) +
			(offset - PraminOffset);
		std::uint32_t value = 0;
		if (m_ram && physical + sizeof(value) <= m_ramSize)
			std::memcpy(&value, m_ram + physical, sizeof(value));
		return value;
	}
	return 0u;
}

void CxbxUwpNv2aProducer::UpdateInterruptLine()
{
	constexpr std::uint32_t Nv2aSource = 1u;
	const bool asserted = HasEnabledInterrupt();
	const bool changed = asserted != m_interruptLineAsserted;
	const bool hasExceptionalSource =
		(Register(PfifoIntr) & Register(PfifoIntrEnable)) != 0 ||
		(Register(PgraphIntr) & Register(PgraphIntrEnable)) != 0;
	// PCRTC toggles twice per displayed frame. Log its first few transitions and
	// one sample every five seconds, while PFIFO/PGRAPH diagnostics stay lossless.
	const bool periodicVblankSample = asserted &&
		(m_vblankCount <= 3 || (m_vblankCount % 300) == 0);
	if (changed && m_logger && (hasExceptionalSource || periodicVblankSample)) {
		char line[416] = {};
		sprintf_s(line,
			"[uwp-nv2a:irq] linha=%s VBLANK=%llu PFIFO=%08X/%08X PGRAPH=%08X/%08X PCRTC=%08X/%08X NSOURCE=%08X TRAP=%08X DATA=%08X CLASS=%03X GET=%08X PUT=%08X.\r\n",
			asserted ? "ativa" : "inativa",
			static_cast<unsigned long long>(m_vblankCount),
			Register(PfifoIntr), Register(PfifoIntrEnable),
			Register(PgraphIntr), Register(PgraphIntrEnable),
			Register(PcrtcIntr), Register(PcrtcIntrEnable),
			Register(PgraphNsource), Register(PgraphTrappedAddress),
			Register(PgraphTrappedDataLow), Register(PgraphContextSwitch1) & 0xFFFu,
			m_dmaGet, m_pendingDmaPut);
		m_logger(line);
	}
	m_interruptLineAsserted = asserted;
	if (asserted) CxbxUwpAssertDeviceInterrupt(CxbxUwpDeviceIrq::Gpu, Nv2aSource);
	else CxbxUwpAcknowledgeDeviceInterrupt(CxbxUwpDeviceIrq::Gpu, Nv2aSource);
}

void CxbxUwpNv2aProducer::SignalVblank()
{
	m_registers[PcrtcIntr] |= 1u;
	UpdateInterruptLine();
}

void CxbxUwpNv2aProducer::Tick()
{
	const auto elapsed = std::chrono::steady_clock::now().time_since_epoch();
	const auto now = static_cast<std::uint64_t>(
		std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
	if (!m_nextVblankMicros) m_nextVblankMicros = now + VblankPeriodMicros;
	if (now < m_nextVblankMicros) return;

	// Interrupt status is level-triggered, so missed refreshes coalesce into one
	// pending PCRTC bit while the guest ISR is busy. Keep the phase stable rather
	// than drifting with executor timeslice latency.
	const auto elapsedFrames = 1u + (now - m_nextVblankMicros) / VblankPeriodMicros;
	m_nextVblankMicros += elapsedFrames * VblankPeriodMicros;
	m_vblankCount += elapsedFrames;
	SignalVblank();
}
