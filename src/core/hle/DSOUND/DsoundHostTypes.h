#pragma once

// The Windows SDK hides DirectSound declarations when WINAPI_FAMILY is UWP.
// Cxbx still needs the data structures and COM interface declarations while
// its UWP host implementation is supplied by SDL3 and does not link dsound.lib.
#include <Windows.h>
#include <mmreg.h>

#if defined(CXBXR_UWP)
# undef WINAPI_FAMILY
# define WINAPI_FAMILY WINAPI_FAMILY_DESKTOP_APP
# include <dsound.h>
# undef WINAPI_FAMILY
# define WINAPI_FAMILY WINAPI_FAMILY_APP
#else
# include <dsound.h>
#endif
