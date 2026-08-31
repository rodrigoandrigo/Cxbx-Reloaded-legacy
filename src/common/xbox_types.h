// ******************************************************************
// *
// *  This file is part of the Cxbx project.
// *
// *  Cxbx and Cxbe are free software; you can redistribute them
// *  and/or modify them under the terms of the GNU General Public
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
// *  (c) 2020 ergo720
// *
// *  All rights reserved
// *
// ******************************************************************

#pragma once

#include <cstdint>
#include <cstddef>
#include <climits>
#include <cuchar>


namespace xbox
{
	// Xbox kernel ABI pointers are always 32-bit.  On an x64 host MSVC's
	// __ptr32 keeps their storage/layout correct while still allowing direct
	// access to Cxbx's low 4 GiB guest address space.
	#if defined(_MSC_VER) && defined(_WIN64)
	#define XBOX_PTR32 __ptr32
	#else
	#define XBOX_PTR32
	#endif

	template<typename T>
	using ptr_xt = T* XBOX_PTR32;

	// ******************************************************************
	// * Calling conventions
	// ******************************************************************
	// TODO: Remove __stdcall once lib86cpu is implemented.
	#define XBOXAPI             __stdcall
	#define XCALLBACK           XBOXAPI

	// ******************************************************************
	// * Basic types
	// ******************************************************************
	using void_xt = void;
	using char_xt = char;
	using cchar_xt = char;
	using wchar_xt = char16_t;
	using short_xt = std::int16_t;
	using cshort_xt = std::int16_t;
	using long_xt = std::int32_t;
	using uchar_xt = std::uint8_t;
	using byte_xt = std::uint8_t;
	using boolean_xt = std::uint8_t;
	using ushort_xt = std::uint16_t;
	using word_xt = std::uint16_t;
	using ulong_xt = std::uint32_t;
	using dword_xt = std::uint32_t;
	using size_xt = ulong_xt;
	using access_mask_xt = ulong_xt;
	using physical_address_xt = ulong_xt;
	using uint_xt = std::uint32_t;
	using int_xt = std::int32_t;
	using int_ptr_xt = int_xt;
	using long_ptr_xt = long_xt;
	using ulong_ptr_xt = ulong_xt;
	using longlong_xt = std::int64_t;
	using ulonglong_xt = std::uint64_t;
	using quad_xt = std::uint64_t; // 8 byte aligned 8 byte long
	using bool_xt = std::int32_t;
	using hresult_xt = long_xt;
	using ntstatus_xt = long_xt;
	using float_xt = float;
	/*! addr is the type of a physical address */
	using addr_xt = std::uint32_t;
	/*! zero is the type of null address or value */
	inline constexpr addr_xt zero = 0;
	/*! zeroptr is the type of null pointer address */
	using zeroptr_xt = std::nullptr_t;
	inline constexpr zeroptr_xt zeroptr = nullptr;

	// ******************************************************************
	// * Pointer types
	// ******************************************************************
	using PCHAR = ptr_xt<char_xt>;
	using PSZ = ptr_xt<char_xt>;
	using PCSZ = ptr_xt<const char_xt>;
	using PBYTE = ptr_xt<byte_xt>;
	using PBOOLEAN = ptr_xt<boolean_xt>;
	using PUCHAR = ptr_xt<uchar_xt>;
	using PUSHORT = ptr_xt<ushort_xt>;
	using PUINT = ptr_xt<uint_xt>;
	using PULONG = ptr_xt<ulong_xt>;
	using PDWORD = ptr_xt<dword_xt>;
	using LPDWORD = ptr_xt<dword_xt>;
	using PLONG = ptr_xt<long_xt>;
	using PINT_PTR = ptr_xt<int_ptr_xt>;
	using PVOID = ptr_xt<void_xt>;
	using LPVOID = ptr_xt<void_xt>;
	using HANDLE = ptr_xt<void_xt>;
	using PHANDLE = ptr_xt<HANDLE>;
	using PSIZE_T = ptr_xt<size_xt>;
	using PACCESS_MASK = ptr_xt<access_mask_xt>;
	using PLONGLONG = ptr_xt<longlong_xt>;
	using PQUAD = ptr_xt<quad_xt>;

	// ******************************************************************
	// ANSI (Multi-byte Character) types
	// ******************************************************************
	using LPCH = ptr_xt<char_xt>;
	using PCH = ptr_xt<char_xt>;
	using LPCCH = ptr_xt<const char_xt>;
	using PCCH = ptr_xt<const char_xt>;
	using LPWSTR = ptr_xt<wchar_xt>;
	using PWSTR = ptr_xt<wchar_xt>;
	using LPCWSTR = ptr_xt<const wchar_xt>;
	using PCWSTR = ptr_xt<const wchar_xt>;

	// ******************************************************************
	// Misc
	// ******************************************************************
	typedef struct _XD3DVECTOR {
		float_xt x;
		float_xt y;
		float_xt z;
	} D3DVECTOR;

	template<typename A, typename B>
	inline void CopyD3DVector(A& a, const B& b)
	{
		a.x = b.x;
		a.y = b.y;
		a.z = b.z;
	}

	// ******************************************************************
	// Type assertions
	// ******************************************************************
	static_assert(CHAR_BIT == 8);
	static_assert(sizeof(char16_t) == 2);

	// ******************************************************************
	// Defines
	// ******************************************************************
	constexpr uint_xt max_path{ 260 }; // Xbox file path max limitation
}
