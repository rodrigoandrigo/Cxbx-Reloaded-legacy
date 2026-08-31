# This must be selected when configuring a fresh build tree. It makes the
# Visual Studio generator produce a Windows Store/AppContainer target instead
# of a desktop Win32 DLL with desktop default-library imports.
set(CMAKE_SYSTEM_NAME WindowsStore)
set(CMAKE_SYSTEM_VERSION 10.0)

# ApplicationTypeRevision stays at 10.0 for Visual Studio's UWP targets, but
# the SDK selected by those targets must name an installed UAP SDK exactly.
set(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION 10.0.26100.0)
