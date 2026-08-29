#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <unordered_map>
#include <vector>

// UWP-native NV2A/PFIFO/PGRAPH front-end. It owns no desktop/Win32 object:
// guest MMIO and DMA are consumed on the executor thread and completed colour
// surfaces are handed to the XAML/D3D11 presentation queue. Method encodings
// are kept in lockstep with devices/video/nv2a_regs.h.
class CxbxUwpNv2aProducer final
{
public:
	using LogCallback = void (*)(const char* text);

	static constexpr std::uint32_t MmioBase = 0xFD000000u;
	static constexpr std::uint32_t MmioSize = 0x01000000u;

	CxbxUwpNv2aProducer(std::uint8_t* ram, std::size_t ramSize, LogCallback logger = nullptr);
	~CxbxUwpNv2aProducer();
	std::uint8_t Read8(std::uint32_t address) const;
	std::uint16_t Read16(std::uint32_t address) const;
	std::uint32_t Read32(std::uint32_t address) const;
	std::uint64_t Read64(std::uint32_t address) const;
	void Write8(std::uint32_t address, std::uint8_t value);
	void Write16(std::uint32_t address, std::uint16_t value);
	void Write32(std::uint32_t address, std::uint32_t value);
	void Write64(std::uint32_t address, std::uint64_t value);
	// Advance the free-running PCRTC clock. VBlank is a display timing source,
	// not a side effect of Present or of a guest flip command.
	void Tick();
	void SetPixelShadersEnabled(bool enabled) { m_pixelShadersEnabled = enabled; }
	void ConfigureDisplay(std::uint32_t mode, std::uint32_t format,
		std::uint32_t pitch, std::uint32_t frameBuffer);

public: // POD shader/rasterizer values are public so translation helpers stay allocation-free.
	struct Vec4 { float x = 0, y = 0, z = 0, w = 1; };
	struct Vertex {
		std::array<Vec4, 16> attributes = {};
		Vec4 position = {};
		Vec4 diffuse = { 1, 1, 1, 1 };
		Vec4 specular = {};
		float fog = 0;
		std::array<Vec4, 4> texcoord = {};
	};
	struct VertexArray { std::uint32_t offset = 0, format = 0; };
	struct TextureStage {
		std::uint32_t offset = 0, format = 0, address = 0, control0 = 0;
		std::uint32_t control1 = 0, filter = 0, rect = 0, palette = 0;
		std::uint32_t borderColor = 0;
	};
	struct ColorF { float r = 0, g = 0, b = 0, a = 1; };

private:
	void ResetState();
	void ConsumePushBuffer(std::uint32_t put, std::uint32_t channel);
	bool CanRunDmaChannel(std::uint32_t channel) const;
	void TryRunCurrentDmaChannel();
	void SetDmaPusherError(std::uint32_t error, std::uint32_t get,
		std::uint32_t put, std::uint32_t word);
	void ExecuteMethod(std::uint32_t subchannel, std::uint32_t method, std::uint32_t value);
	void BeginPrimitive(std::uint32_t mode);
	void EndPrimitive();
	void DrawArrays(std::uint32_t start, std::uint32_t count);
	void DrawIndexed();
	void DrawVertices(const std::vector<Vertex>& vertices, const std::vector<std::uint32_t>* indices);
	bool FetchVertex(std::uint32_t index, Vertex& vertex) const;
	bool DecodeInlineVertices(std::vector<Vertex>& vertices) const;
	void RunVertexProgram(Vertex& vertex) const;
	void EmitInlineVertex();
	void RasterizePoint(const Vertex& a);
	void RasterizeLine(const Vertex& a, const Vertex& b);
	void RasterizeTriangle(const Vertex& a, const Vertex& b, const Vertex& c);
	ColorF ShadePixel(const Vertex& v) const;
	ColorF SampleTexture(std::uint32_t stage, const Vec4& coordinate, bool applyFilter = true) const;
	ColorF ApplyRegisterCombiners(const Vertex& v, const std::array<ColorF, 4>& textures) const;
	bool FragmentTests(std::uint32_t x, std::uint32_t y, float z, ColorF& source);
	void WritePixel(std::uint32_t x, std::uint32_t y, const ColorF& source);
	ColorF ReadPixel(std::uint32_t x, std::uint32_t y) const;
	void ClearSurface(std::uint32_t flags);
	void CompositeOverlay(std::vector<std::uint32_t>& frame) const;
	void SubmitSurface();
	void SignalVblank();
	void UpdateInterruptLine();
	bool HasEnabledInterrupt() const;
	std::uint32_t Register(std::uint32_t offset) const;
	bool ReadWord(std::uint32_t address, std::uint32_t& value) const;
	bool ReadBytes(std::uint64_t address, void* destination, std::size_t size) const;
	std::uint32_t PhysicalAddress(std::uint32_t address) const;
	bool ResolveHandle(std::uint32_t handle, std::uint32_t channel, std::uint32_t& instance, std::uint32_t& objectClass) const;
	std::uint32_t ResolveDmaBase(std::uint32_t instance, std::uint32_t* limit = nullptr) const;
	std::uint32_t ResolveDmaFrame(std::uint32_t instance) const;
	void Execute2DBlit();

	std::uint8_t* m_ram;
	std::size_t m_ramSize;
	LogCallback m_logger = nullptr;
	std::unordered_map<std::uint32_t, std::uint32_t> m_registers;
	std::array<std::uint32_t, 8> m_subchannelObject = {};
	std::array<std::uint32_t, 8> m_subchannelClass = {};
	std::array<Vec4, 16> m_inlineAttributes = {};
	std::array<std::uint8_t, 16> m_inlineAttributeMask = {};
	std::vector<Vertex> m_inlineVertices;
	std::vector<std::uint32_t> m_inlineArray;
	std::vector<std::uint32_t> m_indices;
	std::uint32_t m_dmaGet = 0, m_dmaChannel = 0;
	std::uint64_t m_nextVblankMicros = 0, m_vblankCount = 0;
	std::uint32_t m_pendingDmaPut = 0, m_pendingDmaChannel = 0;
	bool m_pgraphTrapPending = false, m_interruptLineAsserted = false;
	std::array<std::uint32_t, 32> m_dmaCallStack = {};
	std::uint32_t m_dmaStackDepth = 0, m_dmaMethod = 0, m_dmaSubchannel = 0, m_dmaRemaining = 0;
	bool m_dmaIncrement = true, m_dmaParserSuspended = false;
	std::uint32_t m_colorOffset = 0, m_zetaOffset = 0;
	std::uint32_t m_colorPitch = 0, m_zetaPitch = 0;
	std::uint32_t m_width = 640;
	std::uint32_t m_height = 480;
	std::uint32_t m_surfaceFormat = 5;
	std::uint32_t m_clipX = 0, m_clipY = 0;
	std::uint32_t m_beginEnd = 0;
	std::array<VertexArray, 16> m_vertexArrays = {};
	std::array<TextureStage, 4> m_textures = {};
	std::array<float, 4> m_viewportOffset = { 0, 0, 0, 0 };
	std::array<float, 4> m_viewportScale = { 1, 1, 1, 1 };
	std::array<std::uint32_t, 0x800> m_pgraphMethods = {};
	std::array<std::array<std::uint32_t, 4>, 136> m_transformProgram = {};
	std::array<Vec4, 192> m_transformConstants = {};
	std::uint32_t m_programLoad = 0, m_programStart = 0, m_constantLoad = 0, m_transformMode = 0;
	std::uint32_t m_colorClearValue = 0, m_zstencilClearValue = 0;
	std::uint32_t m_clearRectHorizontal = 0x027F0000u, m_clearRectVertical = 0x01DF0000u;
	std::uint32_t m_colorMask = 0x01010101u;
	std::uint32_t m_alphaFunc = 0x0207u, m_alphaRef = 0, m_depthFunc = 0x0203u;
	std::uint32_t m_stencilFunc = 0x0207u, m_stencilRef = 0, m_stencilFuncMask = 0xFFu, m_stencilWriteMask = 0xFFu;
	std::uint32_t m_stencilFail = 0x1E00u, m_stencilZFail = 0x1E00u, m_stencilZPass = 0x1E00u;
	std::uint32_t m_blendSrc = 1u, m_blendDst = 0u, m_blendEquation = 0x8006u, m_blendColor = 0;
	std::uint32_t m_cullFace = 0x0405u, m_frontFace = 0x0901u;
	std::uint32_t m_frontPolygonMode = 0x1B02u, m_backPolygonMode = 0x1B02u, m_shadeMode = 0x1D01u;
	std::uint32_t m_logicOp = 0x1503u, m_fogMode = 0x2601u, m_fogColor = 0, m_pointSize = 8, m_lineWidth = 8;
	std::array<float, 3> m_fogParams = { 0, 1, 0 };
	std::uint32_t m_shaderStageProgram = 0, m_shaderOtherStageInput = 0, m_combinerControl = 0;
	bool m_alphaTest = false, m_blend = false, m_cull = false, m_depthTest = false, m_depthWrite = true, m_stencilTest = false, m_logicOpEnabled = false, m_fogEnabled = false;
	std::uint32_t m_surface2DSourceDma = 0, m_surface2DDestinationDma = 0, m_surface2DFormat = 0;
	std::uint32_t m_surface2DSourcePitch = 0, m_surface2DDestinationPitch = 0, m_surface2DSourceOffset = 0, m_surface2DDestinationOffset = 0;
	std::uint32_t m_blitOperation = 3, m_blitIn = 0, m_blitOut = 0, m_blitSize = 0;
	std::uint32_t m_semaphoreDma = 0, m_reportDma = 0, m_semaphoreOffset = 0, m_zpassCount = 0;
	bool m_zpassCountEnabled = false;
	bool m_pixelShadersEnabled = true;
	bool m_loggedFirstPushBuffer = false;
	bool m_loggedFirstFrame = false;
};

bool CxbxUwpConfigureNv2aDisplay(std::uint32_t mode, std::uint32_t format,
	std::uint32_t pitch, std::uint32_t frameBuffer);
bool CxbxUwpWriteNv2aRegister(std::uint32_t offset, std::uint32_t value);
