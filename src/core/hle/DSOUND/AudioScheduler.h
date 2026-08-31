#pragma once

#include <cstdint>

// Narrow scheduler-facing audio API. Keeping these declarations independent
// of the desktop DirectSound types lets Timer.cpp build for UWP while the
// complete audio implementation remains selected by the platform backend.
void dsound_worker();
uint64_t dsound_tick(uint64_t now);
