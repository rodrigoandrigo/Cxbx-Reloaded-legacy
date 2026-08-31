cmake_minimum_required (VERSION 3.12)
project(cxbxr-emu)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)

# Suppress extra stuff from generated solution
set(CMAKE_SUPPRESS_REGENERATION true)

# Force exclude default libraries being included
#set(CMAKE_CXX_STANDARD_LIBRARIES "")

include_directories(
 "${CXBXR_ROOT_DIR}/src"
 "${CXBXR_ROOT_DIR}/src/common"
 "${CXBXR_ROOT_DIR}/src/common/Win32"
 "${CXBXR_ROOT_DIR}/import/OpenXDK/include"
 "${CXBXR_ROOT_DIR}/import/DirectX9/include"
 "${CXBXR_ROOT_DIR}/import/distorm/include"
 "${CXBXR_ROOT_DIR}/import/libusb/libusb"
 "${CXBXR_ROOT_DIR}/import/simpleini"
 "${CXBXR_ROOT_DIR}/import/winpcap/Include"
 "${CXBXR_ROOT_DIR}/import/rapidhash"
 "${CXBXR_SHADER_GEN_INCLUDE_DIR}"
)

link_directories(
 "${CXBXR_ROOT_DIR}/import/distorm/lib/Win32"
 "${CXBXR_ROOT_DIR}/import/DirectX9/lib"
 "${CXBXR_ROOT_DIR}/import/winpcap/Lib"
)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
 add_compile_definitions(
  _CRT_SECURE_NO_WARNINGS
  LTM_DESC
  USE_LTM
  LTC_NO_TEST
  LTC_NO_CIPHERS
  LTC_NO_HASHES
  LTC_NO_MACS
  LTC_NO_PRNGS
  LTC_NO_MISC
  LTC_NO_PROTOTYPES

 )

 if(CXBXR_UWP_CORE)
  # FromApp file/mapping declarations are gated on Windows 10 RS3+.
  add_compile_definitions(_WIN32_WINNT=0x0A00 NTDDI_VERSION=0x0A000005)
 else()
  # Windows 7 minimum requirement for the desktop build.
  add_compile_definitions(_WIN32_WINNT=0x0601)
 endif()
 add_compile_options(
  /EHs
  /MP
  /GF
  /arch:SSE2
 )
endif()

add_compile_definitions(
 NOMINMAX
 CXBXR_EMU
 CXBXR_EMU_EXPORTS
)

if(CXBXR_UWP_CORE)
 add_compile_definitions(
  CXBXR_UWP=1
  WINAPI_FAMILY=WINAPI_FAMILY_APP
  # SimpleIni's portable byte-wise comparator avoids desktop-only _mbsicmp.
  SI_NO_MBCS=1
 )
endif()

file (GLOB RESOURCES
 "${CXBXR_ROOT_DIR}/CONTRIBUTORS"
 "${CXBXR_ROOT_DIR}/COPYING"
 "${CXBXR_ROOT_DIR}/README.md"
)

source_group(TREE ${CXBXR_ROOT_DIR}/import PREFIX import FILES
 ${CXBXR_HEADER_EMU_IMPORT}
)

source_group(TREE ${CXBXR_ROOT_DIR}/src PREFIX header FILES
 ${CXBXR_HEADER_GUIv1}
 ${CXBXR_HEADER_COMMON}
 ${CXBXR_HEADER_EMU}
 "${CXBXR_ROOT_DIR}/src/emulator/targetver.h"
)

# The desktop render window imports USER32/GDI and cannot be part of an
# AppContainer DLL. HostDevice retains shared D3D helpers but compiles its
# HWND path out under CXBXR_UWP; HostWindow is replaced completely.
if(CXBXR_UWP_CORE)
 list(REMOVE_ITEM CXBXR_SOURCE_EMU
  "${CXBXR_ROOT_DIR}/src/core/hle/D3D8/Rendering/Backend/HostWindow.cpp"
  "${CXBXR_ROOT_DIR}/src/devices/x86/EmuX86.cpp"
 )
 list(APPEND CXBXR_SOURCE_EMU
  "${CXBXR_ROOT_DIR}/src/core/hle/D3D8/Rendering/Backend/HostWindowUwp.cpp"
  "${CXBXR_ROOT_DIR}/src/devices/x86/EmuX86Tcg.cpp"
 )
endif()

source_group(TREE ${CXBXR_ROOT_DIR}/import PREFIX import FILES
 ${CXBXR_SOURCE_EMU_IMPORT}
)

source_group(TREE ${CXBXR_ROOT_DIR}/src PREFIX source FILES
 ${CXBXR_SOURCE_GUIv1}
 ${CXBXR_SOURCE_COMMON}
 ${CXBXR_SOURCE_EMU}
 "${CXBXR_ROOT_DIR}/src/emulator/cxbxr-emu.cpp"
 "${CXBXR_ROOT_DIR}/src/emulator/CxbxEmbed.cpp"
 "${CXBXR_ROOT_DIR}/src/emulator/dllmain.cpp"
)

source_group(TREE ${CXBXR_ROOT_DIR} FILES ${RESOURCES})

add_library(${PROJECT_NAME} SHARED ${RESOURCES}
 ${CXBXR_HEADER_COMMON}
 ${CXBXR_HEADER_EMU_IMPORT}
 ${CXBXR_HEADER_EMU}
 "${CXBXR_ROOT_DIR}/src/emulator/targetver.h"
 ${CXBXR_SOURCE_COMMON}
 ${CXBXR_SOURCE_EMU_IMPORT}
 ${CXBXR_SOURCE_EMU}
 ${CXBXR_GIT_VERSION_H}
 "${CXBXR_ROOT_DIR}/src/emulator/cxbxr-emu.cpp"
 "${CXBXR_ROOT_DIR}/src/emulator/CxbxEmbed.cpp"
 "${CXBXR_ROOT_DIR}/src/emulator/dllmain.cpp"
)

# Link and compile flags
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")

 if(CXBXR_UWP_CORE)
  set(CXBXR_WPCAP_DELAYLOAD "")
 else()
  set(CXBXR_WPCAP_DELAYLOAD "/DELAYLOAD:wpcap.dll")
 endif()

 set_target_properties(${PROJECT_NAME} PROPERTIES
  LINK_FLAGS "
  /INCREMENTAL:NO \
  /LARGEADDRESSAWARE \
  /SAFESEH:NO \
  /STACK:65536,65536 \
  /NODEFAULTLIB:libcmt \
  ${CXBXR_WPCAP_DELAYLOAD} \
  "
  LINK_FLAGS_RELEASE "
  /LTCG \
  /DEBUG \
  /ignore:4099 \
  "
 )

 # Set optimization options for release build
 # Replace CMake's default /Ob2 with /Ob3 for aggressive inlining
 string(REPLACE "/Ob2" "/Ob3" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
 set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} \
  /Zi \
  /Oi \
  /Ot \
  /GL \
  \
  /GS- \
  /Gy \
  /Qpar \
  "
 )

 # Auto-detect files that use __try/__except and disable /GL on them.
 # Works around an MSVC bug where /GL silently switches SEH3 to SEH4
 # (adding an unexpected security cookie), even when /GS- is specified.
 # SEH4 frames break exception unwinding when mixed with Xbox SEH3 frames.
 # See: https://developercommunity.visualstudio.com/t/10693061
 set(ALL_EMU_SOURCES
  ${CXBXR_SOURCE_COMMON}
  ${CXBXR_SOURCE_EMU_IMPORT}
  ${CXBXR_SOURCE_EMU}
  "${CXBXR_ROOT_DIR}/src/emulator/cxbxr-emu.cpp"
  "${CXBXR_ROOT_DIR}/src/emulator/CxbxEmbed.cpp"
  "${CXBXR_ROOT_DIR}/src/emulator/dllmain.cpp"
 )
 foreach(src IN LISTS ALL_EMU_SOURCES)
  if(EXISTS "${src}")
   file(STRINGS "${src}" seh_hits REGEX "^[ \t]*__try[ \t{]")
   if(seh_hits)
    set_source_files_properties("${src}" PROPERTIES COMPILE_FLAGS "/GL-")
    message(STATUS "Applied /GL- to ${src} (contains __try/__except)")
   endif()
  endif()
 endforeach()
endif()

# Windows libraries. A UWP core must resolve the all-device Win32 API set
# through WindowsApp.lib rather than acquiring desktop imports from the
# compatibility DLLs. D3D11/DXGI/D3DCompiler remain explicit because the UWP
# renderer uses those supported graphics APIs directly.
if(CXBXR_UWP_CORE)
 set(WINS_LIB WindowsApp d3d11 dxgi d3dcompiler dxguid)
else()
 set(WINS_LIB
  legacy_stdio_definitions
  delayimp
  dinput8
  dxguid
  odbc32
  odbccp32
  Shlwapi
  dxerr9
  ws2_32
  dsound
  winmm
  ddraw
  dbghelp
  comctl32
  XINPUT9_1_0
  Iphlpapi
  wpcap
  d3d11
  dxgi
  d3dcompiler
 )
endif()

set(CXBXR_SDL_TARGET SDL2)
set(CXBXR_INPUT_TARGET libusb)
if(CXBXR_UWP_CORE)
 set(CXBXR_SDL_TARGET SDL3::SDL3)
 set(CXBXR_INPUT_TARGET)
 target_compile_definitions(${PROJECT_NAME} PRIVATE SDL_ENABLE_OLD_NAMES=1)
endif()

target_link_libraries(${PROJECT_NAME}
 PUBLIC libXbSymbolDatabase
 subhook
 libtomcrypt
 ${CXBXR_SDL_TARGET}
 imgui
 ${CXBXR_INPUT_TARGET}
 nv2a_vsh_emulator
 nv2a_vsh_disassembler
 mio::mio_min_winapi

 ${WINS_LIB}
)

install(TARGETS ${PROJECT_NAME}
  RUNTIME DESTINATION bin
)

if(CXBXR_UWP_CORE)
 add_dependencies(${PROJECT_NAME} misc-batch compile-shaders)
else()
 add_dependencies(${PROJECT_NAME} cxbxr-ldr misc-batch compile-shaders)
endif()

# Try to stop cmake from building hlsl files
# Which are all currently loaded at runtime only
set_source_files_properties(
  ${CXBXR_HEADER_HLSL}
  PROPERTIES
  HEADER_FILE_ONLY TRUE
  VS_TOOL_OVERRIDE "None"
)
