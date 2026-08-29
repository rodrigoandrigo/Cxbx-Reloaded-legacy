#include "UwpAudioHost.h"
#include "..\..\src\core\kernel\init\UwpDeviceBus.h"

#include <Windows.h>
#include <xaudio2.h>
#include <wrl/client.h>

#include <algorithm>
#include <cstring>
#include <mutex>
#include <unordered_set>
#include <vector>

using Microsoft::WRL::ComPtr;

struct CxbxUwpAudioHost::Impl final : IXAudio2VoiceCallback
{
	struct Packet { std::vector<std::uint8_t> bytes; };
	ComPtr<IXAudio2> engine;
	IXAudio2MasteringVoice* mastering = nullptr;
	IXAudio2SourceVoice* source = nullptr;
	std::mutex mutex;
	std::unordered_set<Packet*> packets;
	std::uint32_t sampleRate = 0;
	bool closing = false;
	float volume = 1.0f;
	bool muted = false;

	Impl()
	{
		if (FAILED(XAudio2Create(&engine, 0, XAUDIO2_DEFAULT_PROCESSOR))) return;
		if (FAILED(engine->CreateMasteringVoice(&mastering, 2, 48000))) { engine.Reset(); return; }
		CxbxUwpSetAudioSubmitter(&Submit, this);
	}

	~Impl()
	{
		CxbxUwpSetAudioSubmitter(nullptr, nullptr);
		{ std::lock_guard<std::mutex> lock(mutex); closing = true; }
		if (source) { source->Stop(); source->FlushSourceBuffers(); source->DestroyVoice(); source = nullptr; }
		{ std::lock_guard<std::mutex> lock(mutex); for (auto* packet : packets) delete packet; packets.clear(); }
		if (mastering) { mastering->DestroyVoice(); mastering = nullptr; }
		engine.Reset();
	}

	bool Ready() const { return engine && mastering; }
	void ApplyVolume()
	{
		if (mastering) mastering->SetVolume(muted ? 0.0f : volume);
	}

	bool EnsureVoice(std::uint32_t rate)
	{
		rate = (std::max)(8000u, (std::min)(96000u, rate));
		// Xbox output is normally fixed at 48 kHz.  Keep an already running
		// source voice stable; recreating it while XAudio2 completes buffers can
		// deadlock the device callback and is unnecessary for the MCPX path.
		if (source) return true;
		WAVEFORMATEX format = {}; format.wFormatTag = WAVE_FORMAT_PCM; format.nChannels = 2;
		format.nSamplesPerSec = rate; format.wBitsPerSample = 16; format.nBlockAlign = 4;
		format.nAvgBytesPerSec = rate * format.nBlockAlign;
		if (FAILED(engine->CreateSourceVoice(&source, &format, 0, 2.0f, this))) return false;
		sampleRate = rate; return SUCCEEDED(source->Start());
	}

	static void Submit(const std::int16_t* samples, std::uint32_t frames, std::uint32_t rate, void* context)
	{
		auto* self = static_cast<Impl*>(context); if (!self || !samples || !frames) return;
		std::lock_guard<std::mutex> lock(self->mutex); if (self->closing || !self->Ready() || !self->EnsureVoice(rate)) return;
		XAUDIO2_VOICE_STATE state = {}; self->source->GetState(&state);
		if (state.BuffersQueued >= 8) return;
		auto* packet = new Packet; packet->bytes.resize(static_cast<std::size_t>(frames) * 4);
		std::memcpy(packet->bytes.data(), samples, packet->bytes.size()); self->packets.insert(packet);
		XAUDIO2_BUFFER buffer = {}; buffer.AudioBytes = static_cast<UINT32>(packet->bytes.size()); buffer.pAudioData = packet->bytes.data(); buffer.pContext = packet;
		if (FAILED(self->source->SubmitSourceBuffer(&buffer))) { self->packets.erase(packet); delete packet; }
	}

	void STDMETHODCALLTYPE OnVoiceProcessingPassStart(UINT32) override {}
	void STDMETHODCALLTYPE OnVoiceProcessingPassEnd() override {}
	void STDMETHODCALLTYPE OnStreamEnd() override {}
	void STDMETHODCALLTYPE OnBufferStart(void*) override {}
	void STDMETHODCALLTYPE OnLoopEnd(void*) override {}
	void STDMETHODCALLTYPE OnVoiceError(void* context, HRESULT) override { OnBufferEnd(context); }
	void STDMETHODCALLTYPE OnBufferEnd(void* context) override
	{
		std::lock_guard<std::mutex> lock(mutex); auto* packet = static_cast<Packet*>(context);
		if (packets.erase(packet)) delete packet;
	}
};

CxbxUwpAudioHost::CxbxUwpAudioHost() : m_impl(new Impl) {}
CxbxUwpAudioHost::~CxbxUwpAudioHost() { delete m_impl; }
bool CxbxUwpAudioHost::IsReady() const { return m_impl && m_impl->Ready(); }
void CxbxUwpAudioHost::SetVolume(float volume)
{
	if (!m_impl) return;
	m_impl->volume = (std::max)(0.0f, (std::min)(1.0f, volume));
	m_impl->ApplyVolume();
}
void CxbxUwpAudioHost::SetMuted(bool muted)
{
	if (!m_impl) return;
	m_impl->muted = muted;
	m_impl->ApplyVolume();
}
