#include "internal.hpp"
#include "allocator.hpp"
#include "os_mem.hpp"

#include <Windows.h>

#include <cstdio>

void* os_alloc(size_t size)
{
	// VirtualAllocFromApp explicitly rejects executable protection. JIT pages
	// start writable and are changed to execute/read after code emission.
	void* address = VirtualAllocFromApp(nullptr, size, MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);
	if (!address) {
		char message[160] = {};
		sprintf_s(message, "Failed to allocate %zu bytes of UWP JIT memory (Win32 %lu)",
			size, GetLastError());
		throw lc86_exp_abort(message, lc86_status::no_memory);
	}
	return address;
}

void os_make_writable(void* address, size_t size)
{
	DWORD oldProtection = 0;
	if (!VirtualProtectFromApp(address, size, PAGE_READWRITE, &oldProtection)) {
		char message[176] = {};
		sprintf_s(message, "Failed to make %zu bytes of UWP JIT memory writable (Win32 %lu)",
			size, GetLastError());
		throw lc86_exp_abort(message, lc86_status::no_memory);
	}
}

void os_free(void* address)
{
	if (address) VirtualFree(address, 0, MEM_RELEASE);
}

void os_flush_instr_cache(void* address, size_t size)
{
	DWORD oldProtection = 0;
	if (!VirtualProtectFromApp(address, size, PAGE_EXECUTE_READ, &oldProtection)) {
		char message[176] = {};
		sprintf_s(message, "Failed to make %zu bytes of UWP JIT memory executable (Win32 %lu)",
			size, GetLastError());
		throw lc86_exp_abort(message, lc86_status::no_memory);
	}
	if (!FlushInstructionCache(GetCurrentProcess(), address, size)) {
		char message[160] = {};
		sprintf_s(message, "Failed to flush the UWP JIT instruction cache (Win32 %lu)", GetLastError());
		throw lc86_exp_abort(message, lc86_status::internal_error);
	}
}
