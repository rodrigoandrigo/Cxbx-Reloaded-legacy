#pragma once

#include <cstdint>

class CxbxUwpAudioHost final
{
public:
	CxbxUwpAudioHost();
	~CxbxUwpAudioHost();
	CxbxUwpAudioHost(const CxbxUwpAudioHost&) = delete;
	CxbxUwpAudioHost& operator=(const CxbxUwpAudioHost&) = delete;
	bool IsReady() const;
	void SetVolume(float volume);
	void SetMuted(bool muted);

private:
	struct Impl;
	Impl* m_impl;
};
