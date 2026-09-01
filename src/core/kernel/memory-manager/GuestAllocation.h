#pragma once

#include "core/kernel/memory-manager/VMManager.h"

#include <cstddef>
#include <cstring>
#include <type_traits>

// Xbox ABI structures contain 32-bit pointers. In an x64 host build, any
// temporary structure whose address is stored in one of those fields must live
// in the emulated 32-bit address space, never on the native stack or heap.
template<typename T, size_t Count = 1>
class GuestAllocation final
{
public:
	GuestAllocation()
	{
#if defined(CXBXR_UWP)
		m_address = g_VMManager.AllocateSystemMemory(
			xbox::SystemMemoryType, XBOX_PAGE_READWRITE, sizeof(T) * Count, false);
		m_pointer = reinterpret_cast<T*>(static_cast<uintptr_t>(m_address));
#else
		m_pointer = m_storage;
#endif
		if (m_pointer != nullptr) {
			std::memset(m_pointer, 0, sizeof(T) * Count);
		}
	}

	~GuestAllocation()
	{
#if defined(CXBXR_UWP)
		if (m_address != 0) {
			g_VMManager.DeallocateSystemMemory(
				xbox::SystemMemoryType, m_address, sizeof(T) * Count);
		}
#endif
	}

	GuestAllocation(const GuestAllocation&) = delete;
	GuestAllocation& operator=(const GuestAllocation&) = delete;

	T* get() const { return m_pointer; }
	explicit operator bool() const { return m_pointer != nullptr; }
	T& operator[](size_t index) const { return m_pointer[index]; }

private:
#if defined(CXBXR_UWP)
	VAddr m_address = 0;
#else
	T m_storage[Count]{};
#endif
	T* m_pointer = nullptr;
};
