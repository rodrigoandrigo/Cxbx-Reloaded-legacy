#pragma once

#include <string>

#include "devices/x86/CxbxCpuBackend.h"

struct CxbxCpuBackendExports {
	qemu_cxbx_cpu_get_api_version_fn get_api_version{};
	qemu_cxbx_cpu_create_fn create{};
	qemu_cxbx_cpu_destroy_fn destroy{};
	qemu_cxbx_cpu_map_memory_fn map_memory{};
	qemu_cxbx_cpu_unmap_memory_fn unmap_memory{};
	qemu_cxbx_cpu_set_registers_fn set_registers{};
	qemu_cxbx_cpu_get_registers_fn get_registers{};
	qemu_cxbx_cpu_run_fn run{};
	qemu_cxbx_cpu_interrupt_fn interrupt{};
	qemu_cxbx_cpu_request_stop_fn request_stop{};
	qemu_cxbx_cpu_flush_fn flush{};
};

// Configure must be called before Initialize. The name is a packaged DLL name
// under UWP and may be an absolute path for a desktop diagnostic build.
void CxbxCpuBackendConfigure(const char* module_name_utf8);
bool CxbxCpuBackendInitialize(std::string& error);
void CxbxCpuBackendShutdown();
bool CxbxCpuBackendIsLoaded();
const CxbxCpuBackendExports* CxbxCpuBackendGetExports();
