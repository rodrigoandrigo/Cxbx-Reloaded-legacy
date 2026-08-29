#include "UwpD3D11Host.h"
#include "..\..\..\kernel\init\UwpDeviceInterrupts.h"

#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>
#include "UwpGuestFrameVS.h"
#include "UwpGuestFramePS.h"

namespace
{
	std::mutex g_surfaceMutex;
	CxbxUwpD3D11Surface g_surface = {};
	struct GuestFrame
	{
		std::vector<std::uint8_t> pixels;
		UINT width = 0, height = 0, pitch = 0;
		CxbxUwpGuestPixelFormat format = CxbxUwpGuestPixelFormat::Bgra8;
		bool pending = false;
	};
	std::mutex g_frameMutex;
	GuestFrame g_frame;
	std::atomic_bool g_verticalSync{ true };
	std::atomic_bool g_maintainAspectRatio{ true };
	std::atomic_bool g_linearFiltering{ true };
	std::atomic_uint g_renderScale{ 1 };

	void AddReferences(CxbxUwpD3D11Surface& surface)
	{
		if (surface.device) surface.device->AddRef();
		if (surface.context) surface.context->AddRef();
		if (surface.swapChain) surface.swapChain->AddRef();
	}

	void ReleaseReferences(CxbxUwpD3D11Surface& surface)
	{
		if (surface.swapChain) surface.swapChain->Release();
		if (surface.context) surface.context->Release();
		if (surface.device) surface.device->Release();
		surface = {};
	}
}

void CxbxUwpSetD3D11Settings(const CxbxUwpD3D11Settings* settings)
{
	if (!settings) return;
	g_verticalSync.store(settings->verticalSync, std::memory_order_relaxed);
	g_maintainAspectRatio.store(settings->maintainAspectRatio, std::memory_order_relaxed);
	g_linearFiltering.store(settings->linearFiltering, std::memory_order_relaxed);
	g_renderScale.store((std::max)(1u, (std::min)(12u, settings->renderScale)), std::memory_order_relaxed);
}

CxbxUwpD3D11Settings CxbxUwpGetD3D11Settings()
{
	return { g_verticalSync.load(std::memory_order_relaxed),
		g_maintainAspectRatio.load(std::memory_order_relaxed),
		g_linearFiltering.load(std::memory_order_relaxed),
		g_renderScale.load(std::memory_order_relaxed) };
}

HRESULT CxbxUwpRegisterD3D11Surface(const CxbxUwpD3D11Surface* surface)
{
	if (!surface || !surface->device || !surface->context || !surface->swapChain) {
		return E_INVALIDARG;
	}

	std::lock_guard<std::mutex> lock(g_surfaceMutex);
	CxbxUwpD3D11Surface replacement = *surface;
	AddReferences(replacement);
	ReleaseReferences(g_surface);
	g_surface = replacement;
	return S_OK;
}

HRESULT CxbxUwpAcquireD3D11Surface(CxbxUwpD3D11Surface* surface)
{
	if (!surface) return E_POINTER;

	std::lock_guard<std::mutex> lock(g_surfaceMutex);
	if (!g_surface.device || !g_surface.context || !g_surface.swapChain) {
		*surface = {};
		return DXGI_ERROR_NOT_CURRENTLY_AVAILABLE;
	}

	*surface = g_surface;
	AddReferences(*surface);
	return S_OK;
}

void CxbxUwpReleaseD3D11Surface(CxbxUwpD3D11Surface* surface)
{
	if (!surface) return;
	ReleaseReferences(*surface);
}

void CxbxUwpResetD3D11Surface()
{
	std::lock_guard<std::mutex> lock(g_surfaceMutex);
	ReleaseReferences(g_surface);
}

HRESULT CxbxUwpSubmitGuestFrame(const void* pixels, UINT width, UINT height,
	UINT pitch, CxbxUwpGuestPixelFormat format)
{
	const UINT bytesPerPixel = format == CxbxUwpGuestPixelFormat::Rgb565 ? 2u : 4u;
	if (!pixels || !width || !height || pitch < width * bytesPerPixel ||
		width > 4096 || height > 4096 || static_cast<std::uint64_t>(pitch) * height > 64ull * 1024 * 1024) {
		return E_INVALIDARG;
	}
	std::lock_guard<std::mutex> lock(g_frameMutex);
	g_frame.pixels.resize(static_cast<std::size_t>(pitch) * height);
	std::memcpy(g_frame.pixels.data(), pixels, g_frame.pixels.size());
	g_frame.width = width; g_frame.height = height; g_frame.pitch = pitch;
	g_frame.format = format; g_frame.pending = true;
	return S_OK;
}

HRESULT CxbxUwpRenderSubmittedFrame()
{
	GuestFrame frame;
	{
		std::lock_guard<std::mutex> lock(g_frameMutex);
		if (!g_frame.pending) return S_FALSE;
		frame = std::move(g_frame);
		g_frame.pending = false;
	}
	CxbxUwpD3D11Surface surface = {};
	HRESULT result = CxbxUwpAcquireD3D11Surface(&surface);
	if (FAILED(result)) return result;
	ID3D11Texture2D* target = nullptr;
	result = surface.swapChain->GetBuffer(0, IID_PPV_ARGS(&target));
	if (FAILED(result)) { CxbxUwpReleaseD3D11Surface(&surface); return result; }
	D3D11_TEXTURE2D_DESC targetDesc = {}; target->GetDesc(&targetDesc);
	std::vector<std::uint32_t> converted;
	const void* upload = frame.pixels.data(); UINT uploadPitch = frame.pitch;
	if (frame.format != CxbxUwpGuestPixelFormat::Bgra8) {
		converted.resize(static_cast<std::size_t>(frame.width) * frame.height);
		for (UINT y = 0; y < frame.height; ++y) for (UINT x = 0; x < frame.width; ++x) {
			const auto* source = frame.pixels.data() + static_cast<std::size_t>(y) * frame.pitch; std::uint32_t pixel;
			if (frame.format == CxbxUwpGuestPixelFormat::Rgb565) { std::uint16_t value; std::memcpy(&value, source + x * 2, 2); pixel = 0xFF000000u | (((value >> 11) & 31) * 255 / 31 << 16) | (((value >> 5) & 63) * 255 / 63 << 8) | ((value & 31) * 255 / 31); }
			else { std::memcpy(&pixel, source + x * 4, 4); pixel = (pixel & 0xFF00FF00u) | ((pixel & 0xFFu) << 16) | ((pixel >> 16) & 0xFFu); }
			converted[static_cast<std::size_t>(y) * frame.width + x] = pixel | 0xFF000000u;
		}
		upload = converted.data(); uploadPitch = frame.width * 4;
	}
	D3D11_TEXTURE2D_DESC textureDesc = {}; textureDesc.Width = frame.width; textureDesc.Height = frame.height; textureDesc.MipLevels = textureDesc.ArraySize = 1; textureDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM; textureDesc.SampleDesc.Count = 1; textureDesc.Usage = D3D11_USAGE_DEFAULT; textureDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
	D3D11_SUBRESOURCE_DATA initial = {}; initial.pSysMem = upload; initial.SysMemPitch = uploadPitch;
	ID3D11Texture2D* guestTexture = nullptr; ID3D11ShaderResourceView* guestView = nullptr; ID3D11RenderTargetView* targetView = nullptr; ID3D11VertexShader* vertexShader = nullptr; ID3D11PixelShader* pixelShader = nullptr; ID3D11SamplerState* sampler = nullptr;
	result = surface.device->CreateTexture2D(&textureDesc, &initial, &guestTexture);
	if (SUCCEEDED(result)) result = surface.device->CreateShaderResourceView(guestTexture, nullptr, &guestView);
	if (SUCCEEDED(result)) result = surface.device->CreateRenderTargetView(target, nullptr, &targetView);
	if (SUCCEEDED(result)) result = surface.device->CreateVertexShader(g_UwpGuestFrameVS, sizeof(g_UwpGuestFrameVS), nullptr, &vertexShader);
	if (SUCCEEDED(result)) result = surface.device->CreatePixelShader(g_UwpGuestFramePS, sizeof(g_UwpGuestFramePS), nullptr, &pixelShader);
	const auto settings = CxbxUwpGetD3D11Settings();
	D3D11_SAMPLER_DESC samplerDesc = {}; samplerDesc.Filter = settings.linearFiltering ? D3D11_FILTER_MIN_MAG_MIP_LINEAR : D3D11_FILTER_MIN_MAG_MIP_POINT; samplerDesc.AddressU = samplerDesc.AddressV = samplerDesc.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP; samplerDesc.MaxLOD = D3D11_FLOAT32_MAX;
	if (SUCCEEDED(result)) result = surface.device->CreateSamplerState(&samplerDesc, &sampler);
	if (SUCCEEDED(result)) {
		const float black[4] = {};
		float viewportWidth = static_cast<float>(targetDesc.Width), viewportHeight = static_cast<float>(targetDesc.Height);
		float viewportX = 0.0f, viewportY = 0.0f;
		if (settings.maintainAspectRatio && frame.width && frame.height && targetDesc.Width && targetDesc.Height) {
			const float sourceAspect = static_cast<float>(frame.width) / static_cast<float>(frame.height);
			const float targetAspect = viewportWidth / viewportHeight;
			if (targetAspect > sourceAspect) {
				viewportWidth = viewportHeight * sourceAspect;
				viewportX = (static_cast<float>(targetDesc.Width) - viewportWidth) * 0.5f;
			} else {
				viewportHeight = viewportWidth / sourceAspect;
				viewportY = (static_cast<float>(targetDesc.Height) - viewportHeight) * 0.5f;
			}
		}
		D3D11_VIEWPORT viewport = { viewportX, viewportY, viewportWidth, viewportHeight, 0, 1 };
		surface.context->OMSetRenderTargets(1, &targetView, nullptr); surface.context->ClearRenderTargetView(targetView, black); surface.context->RSSetViewports(1, &viewport);
		surface.context->IASetInputLayout(nullptr); surface.context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST); surface.context->VSSetShader(vertexShader, nullptr, 0); surface.context->PSSetShader(pixelShader, nullptr, 0); surface.context->PSSetShaderResources(0, 1, &guestView); surface.context->PSSetSamplers(0, 1, &sampler); surface.context->Draw(3, 0);
		ID3D11ShaderResourceView* nullView = nullptr; surface.context->PSSetShaderResources(0, 1, &nullView);
	}
	if (sampler) sampler->Release(); if (pixelShader) pixelShader->Release(); if (vertexShader) vertexShader->Release(); if (targetView) targetView->Release(); if (guestView) guestView->Release(); if (guestTexture) guestTexture->Release(); target->Release();
	CxbxUwpReleaseD3D11Surface(&surface);
	return result;
}

void CxbxUwpNotifyD3D11Present(HRESULT presentationResult)
{
	// Present is a host display operation. The NV2A producer raises the guest
	// PCRTC VBLANK source when it processes a flip; pulsing IRQ3 here would
	// deliver an interrupt with PMC/PFIFO/PGRAPH/PCRTC all clear.
	(void)presentationResult;
}
