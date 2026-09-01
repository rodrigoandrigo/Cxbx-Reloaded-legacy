// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
// ******************************************************************
// *
// *  This file is part of Cxbx-Reloaded.
// *
// *  Cxbx-Reloaded is free software; you can redistribute it
// *  and/or modify it under the terms of the GNU General Public
// *  License as published by the Free Software Foundation; either
// *  version 2 of the license, or (at your option) any later version.
// *
// *  This program is distributed in the hope that it will be useful,
// *  but WITHOUT ANY WARRANTY; without even the implied warranty of
// *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// *  GNU General Public License for more details.
// *
// *  You should have recieved a copy of the GNU General Public License
// *  along with this program; see the file COPYING.
// *  If not, write to the Free Software Foundation, Inc.,
// *  59 Temple Place - Suite 330, Bostom, MA 02111-1307, USA.
// *
// *  (c) 2017-2019 Patrick van Logchem <pvanlogchem@gmail.com>
// *  (c) 2019 ergo720
// *
// *  All rights reserved
// *
// ******************************************************************

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <Windows.h> // For DWORD, CALLBACK, VirtualAlloc, LPVOID, SIZE_T, HMODULE 

// NOTE: Cannot be use in loader project due to force exclude std libraries.
//#define DEBUG // Uncomment whenever need to verify memory leaks or bad configure.

#ifdef DEBUG
#include <cstdio> // For printf
#endif
#include <cstdint> // For uint32_t

#include "util/std_extend.hpp"
#include "ReserveAddressRanges.h"
#include "AddressRanges.h"

static uint32_t g_LastReservationBase;
static uint32_t g_LastReservationSize;
static DWORD g_LastReservationError;

static LPVOID AllocateMemoryAt(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect)
{
#if defined(CXBXR_UWP)
	// Guest x86 is translated by TCG, so the host mapping is data and does not
	// require executable permission. Using the AppContainer API also avoids the
	// desktop VirtualAlloc contract inside a packaged UWP process.
	if (protect == PAGE_EXECUTE_READWRITE) {
		protect = PAGE_READWRITE;
	}
	return VirtualAllocFromApp(address, size, allocationType, protect);
#else
	return VirtualAlloc(address, size, allocationType, protect);
#endif
}

static void RememberReservationFailure(uint32_t base, uint32_t size)
{
	g_LastReservationBase = base;
	g_LastReservationSize = size;
	g_LastReservationError = GetLastError();
}

static HANDLE CreateAnonymousMemoryMapping(SIZE_T size)
{
#if defined(CXBXR_UWP)
	return CreateFileMappingFromApp(INVALID_HANDLE_VALUE, nullptr,
		PAGE_EXECUTE_READWRITE, size, nullptr);
#else
	return CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
		PAGE_EXECUTE_READWRITE, 0, static_cast<DWORD>(size), nullptr);
#endif
}

static LPVOID MapMemoryViewAt(HANDLE mapping, uint32_t start, SIZE_T size, bool executable)
{
#if defined(CXBXR_UWP)
	return MapViewOfFile3FromApp(mapping, nullptr,
		reinterpret_cast<LPVOID>(static_cast<uintptr_t>(start)), 0, size, 0,
		executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, nullptr, 0);
#else
	return MapViewOfFileEx(mapping,
		executable ? (FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_EXECUTE) : (FILE_MAP_READ | FILE_MAP_WRITE),
		0, 0, size, reinterpret_cast<LPVOID>(static_cast<uintptr_t>(start)));
#endif
}

// Reserve an address range up to the extend of what the host allows.
bool ReserveMemoryRange(int index, blocks_reserved_t blocks_reserved)
{
	uint32_t Start = XboxAddressRanges[index].Start;
	int Size = XboxAddressRanges[index].Size;
	bool HadAnyFailure = false;

	// Reserve this range in 64 KiB block increments, so that during emulation
	// our memory-management code can VirtualFree() each block individually :

	const DWORD Protect = XboxAddressRanges[index].InitialMemoryProtection;
	bool NeedsReservationTracking = false;
	unsigned int arr_index = BLOCK_REGION_DEVKIT_INDEX_BEGIN;
	static HANDLE hFileMapping1;
	static HANDLE hFileMapping2;

#ifdef DEBUG
	std::printf("DEBUG: ReserveMemoryRange call begin\n");
	std::printf("     : Comment = %s\n", XboxAddressRanges[index].Comment);
#endif

	// Under D3D11, contiguous memory uses VirtualAlloc + MEM_WRITE_WATCH for
	// zero-cost dirty page tracking. Tiled memory is a PAGE_NOACCESS reservation
	// with VEH-based redirect to contiguous memory. This breaks the MapViewOfFileEx
	// alias between 0x80000000 and 0xF0000000 (which is unnecessary under HLE).
	if (Start == PHYSICAL_MAP1_BASE) {
		DWORD allocationType = MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH;
#if defined(CXBXR_UWP)
		// VirtualAllocFromApp does not expose MEM_WRITE_WATCH. The UWP renderer
		// uses its full-upload fallback instead.
		allocationType = MEM_RESERVE | MEM_COMMIT;
#endif
		LPVOID Result = AllocateMemoryAt(
			(LPVOID)Start, Size,
			allocationType,
			PAGE_EXECUTE_READWRITE);
#ifdef DEBUG
		std::printf("     : VirtualAlloc(MEM_WRITE_WATCH); Start = 0x%08X; Result = %p\n", Start, Result);
#endif
		if (Result == nullptr) {
			RememberReservationFailure(Start, static_cast<uint32_t>(Size));
			HadAnyFailure = true;
		}
	} else if (Start == TILED_MEMORY_BASE) {
		LPVOID Result = AllocateMemoryAt(
			(LPVOID)Start, Size,
			MEM_RESERVE,
			PAGE_NOACCESS);
#ifdef DEBUG
		std::printf("     : VirtualAlloc(PAGE_NOACCESS); Start = 0x%08X; Result = %p\n", Start, Result);
#endif
		if (Result == nullptr) {
			RememberReservationFailure(Start, static_cast<uint32_t>(Size));
			HadAnyFailure = true;
		}
	} else
	switch (Start) {
		case PHYSICAL_MAP1_BASE:
			hFileMapping1 = CreateAnonymousMemoryMapping(Size);
			if (hFileMapping1 == nullptr) {
				HadAnyFailure = true;
				break;
			}
			[[fallthrough]];

		case PHYSICAL_MAP2_BASE:
		case TILED_MEMORY_BASE: {
			static bool NeedsInitializationMap = true;

			if (NeedsInitializationMap) {
				hFileMapping2 = CreateAnonymousMemoryMapping(Size);
				if (hFileMapping2 == nullptr) {
					HadAnyFailure = true;
					break;
				}
				NeedsInitializationMap = false;
			}

			LPVOID Result = MapMemoryViewAt(
				(Start == PHYSICAL_MAP1_BASE || Start == TILED_MEMORY_BASE) ? hFileMapping1 : hFileMapping2,
				Start,
				Size,
				(Start == PHYSICAL_MAP1_BASE || Start == PHYSICAL_MAP2_BASE));
#ifdef DEBUG
			std::printf("     : MapViewOfFile; Start = 0x%08X; Result = %p\n", Start, Result);
#endif
			if (Result == nullptr) {
				HadAnyFailure = true;
			}
		}
		break;

		case SYSTEM_MEMORY_BASE:
			// If additional addresses need to be assign in region's block.
			// Then check for nonzero value.
			arr_index = BLOCK_REGION_SYSTEM_INDEX_BEGIN;
			[[fallthrough]];

		case DEVKIT_MEMORY_BASE:
			// arr_index's default is BLOCK_REGION_DEVKIT_INDEX_BEGIN which is zero.
			// Any block region above zero should be place above this case to override zero value.
			//arr_index = BLOCK_REGION_DEVKIT_INDEX_BEGIN;
			NeedsReservationTracking = true;
			[[fallthrough]];

		default: {
			while (Size > 0) {
				SIZE_T BlockSize = (SIZE_T)(Size > BLOCK_SIZE) ? BLOCK_SIZE : Size;
				LPVOID Result = AllocateMemoryAt((LPVOID)Start, BlockSize, MEM_RESERVE, Protect);
				if (Result == nullptr) {
					RememberReservationFailure(Start, static_cast<uint32_t>(BlockSize));
					HadAnyFailure = true;
				}
#ifdef DEBUG
				std::printf("     : Start = %08X; Result = %p;\n", Start, Result);
#endif
				// Handle the next block
				Start += BLOCK_SIZE;
				Size -= BLOCK_SIZE;
				if (NeedsReservationTracking) {
					if (Result != nullptr) {
						blocks_reserved[arr_index / 32] |= (1 << (arr_index % 32));
#ifdef DEBUG
						std::printf("     : arr_index = 0x%08X; set bit = 0x%08X;\n", arr_index, (1 << (arr_index % 32)));
						std::printf("     : blocks_reserved[%08X] = 0x%08X\n", arr_index/32, blocks_reserved[arr_index/32]);
#endif
					}
					arr_index++;
				}
			}
		}
	}
#ifdef DEBUG
	std::printf("     : ReserveMemoryRange call end: HadAnyFailure = %d\n\n", HadAnyFailure);
#endif

	// Only a complete success when the entire request was reserved in a single range
	// (Otherwise, we have either a complete failure, or reserved it partially over multiple ranges)
	return !HadAnyFailure;
}

// Free address range from the host.
void FreeMemoryRange(int index, blocks_reserved_t blocks_reserved)
{
	uint32_t Start = XboxAddressRanges[index].Start, _Start;
	int Size = XboxAddressRanges[index].Size;
	bool NeedsReservationTracking = false;
	unsigned int arr_index = BLOCK_REGION_DEVKIT_INDEX_BEGIN;
#ifdef DEBUG
	std::printf("DEBUG: FreeMemoryRange call begin\n");
	std::printf("     : Comment = %s\n", XboxAddressRanges[index].Comment);
#endif

	// Under D3D11, contiguous and tiled memory were allocated with VirtualAlloc
	// (not MapViewOfFileEx), so they must be freed with VirtualFree.
	if (Start == PHYSICAL_MAP1_BASE || Start == TILED_MEMORY_BASE) {
		(void)VirtualFree((LPVOID)Start, 0, MEM_RELEASE);
#ifdef DEBUG
		std::printf("     : VirtualFree; Start = 0x%08X\n", Start);
#endif
	} else

	switch (Start) {
		case PHYSICAL_MAP1_BASE:
		case PHYSICAL_MAP2_BASE:
		case TILED_MEMORY_BASE: {
			(void)UnmapViewOfFile((LPVOID)Start);
#ifdef DEBUG
			std::printf("     : UnmapViewOfFile; Start = 0x%08X\n", Start);
#endif
		}
		break;

		case SYSTEM_MEMORY_BASE:
			// If additional addresses need to be assign in region's block.
			// Then check for nonzero value.
			arr_index = BLOCK_REGION_SYSTEM_INDEX_BEGIN;
		[[fallthrough]];
		case DEVKIT_MEMORY_BASE: {
			// arr_index's default is BLOCK_REGION_DEVKIT_INDEX_BEGIN which is zero.
			// Any block region above zero should be place above this case to override zero value.
			//arr_index = BLOCK_REGION_DEVKIT_INDEX_BEGIN;
			NeedsReservationTracking = true;
		}
		[[fallthrough]];

		default: {
			while (Size > 0) {
				_Start = Start; // Require to silence C6001's warning complaint
				BOOL Result = VirtualFree((LPVOID)_Start, 0, MEM_RELEASE);
#ifdef DEBUG
				std::printf("     : Start = %08X; Result = %d;\n", Start, Result);
#endif
				// Handle the next block
				Start += BLOCK_SIZE;
				Size -= BLOCK_SIZE;
				if (NeedsReservationTracking) {
					if (Result != 0) {
						blocks_reserved[arr_index / 32] &= ~(1 << (arr_index % 32));
#ifdef DEBUG
						std::printf("     : arr_index = 0x%08X; clear bit = 0x%08X;\n", arr_index, (1 << (arr_index % 32)));
						std::printf("     : blocks_reserved[%08X] = 0x%08X\n", arr_index/32, blocks_reserved[arr_index/32]);
#endif
					}
					arr_index++;
				}
			}
		}
	}
#ifdef DEBUG
	std::printf("     : FreeMemoryRange call end\n\n");
#endif
}

bool ReserveAddressRanges(const unsigned int system, blocks_reserved_t blocks_reserved) {
	// Loop over all Xbox address ranges
	for (size_t i = 0; i < XboxAddressRanges_size; i++) {
		// Skip address ranges that don't match the given flags
		if (!AddressRangeMatchesFlags(i, system))
			continue;

		// Try to reserve each address range
		if (ReserveMemoryRange(i, blocks_reserved))
			continue;

		// Some ranges are allowed to fail reserving
		if (!IsOptionalAddressRange(i)) {
			return false;
		}
	}

	return true;
}

void FreeAddressRanges(const unsigned int system, unsigned int release_systems, blocks_reserved_t blocks_reserved) {
	// If reserved_systems is empty, then there's nothing to be freed up.
	if (release_systems == 0) {
		return;
	}
	// Loop over all Xbox address ranges
	for (size_t i = 0; i < XboxAddressRanges_size; i++) {
		// Skip address ranges that do match specific flag
		if (AddressRangeMatchesFlags(i, system))
			continue;

		// Skip address ranges that doesn't match the reserved flags
		if (!AddressRangeMatchesFlags(i, release_systems))
			continue;

		FreeMemoryRange(i, blocks_reserved);
	}

}

bool AttemptReserveAddressRanges(unsigned int* p_reserved_systems, blocks_reserved_t blocks_reserved) {

	size_t iLast = 0;
	unsigned int reserved_systems = *p_reserved_systems, clear_systems = 0;
	// Loop over all Xbox address ranges
	for (size_t i = 0; i < XboxAddressRanges_size; i++) {

		// Once back to original spot, let's resume.
		if (i == iLast && clear_systems) {
			reserved_systems &= ~clear_systems;
			if (reserved_systems == 0) {
				*p_reserved_systems = 0;
				return false;
			}
			// Resume virtual allocated range.
			clear_systems = 0;
			continue;
		}

		if (clear_systems) {
			// Skip address ranges that doesn't match the given flags
			if (!AddressRangeMatchesFlags(i, clear_systems))
				continue;

			// A range tagged SYSTEM_ALL is shared by Retail, DevKit and
			// Chihiro. Do not free it while downgrading the compatible set if
			// at least one system that remains selected still needs it.
			const unsigned int remaining_systems = reserved_systems & ~clear_systems;
			if (AddressRangeMatchesFlags(i, remaining_systems))
				continue;

			// Release incompatible system's memory range
			FreeMemoryRange(i, blocks_reserved);
		}
		else {
			// Skip address ranges that don't match the given flags
			if (!AddressRangeMatchesFlags(i, reserved_systems))
				continue;

			// Try to reserve each address range
			if (ReserveMemoryRange(i, blocks_reserved))
				continue;

			// Some ranges are allowed to fail reserving
			if (!IsOptionalAddressRange(i)) {
				// If not, then let's free them and downgrade host's limitation.
				clear_systems = AddressRangeGetSystemFlags(i);
				iLast = i;
				i = -1; // Reset index back to zero after for statement's increment.
				continue;
			}
		}
	}

	*p_reserved_systems = reserved_systems;
	return true;
}

bool isSystemFlagSupport(unsigned int reserved_systems, unsigned int assign_system)
{
	if (reserved_systems & assign_system) {
		return true;
	}

	return false;
}

uint32_t GetLastAddressReservationBase()
{
	return g_LastReservationBase;
}

uint32_t GetLastAddressReservationSize()
{
	return g_LastReservationSize;
}

unsigned long GetLastAddressReservationError()
{
	return g_LastReservationError;
}
