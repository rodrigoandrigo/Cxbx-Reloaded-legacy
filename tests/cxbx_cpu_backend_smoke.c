#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "devices/x86/CxbxCpuBackend.h"

#define LOAD_API(module, name) \
    name##_fn name = (name##_fn)GetProcAddress((module), #name)

int main(int argc, char **argv)
{
    HMODULE module;
    QemuCxbxCpuConfig config = {0};
    QemuCxbxCpuRegisters registers = {0};
    QemuCxbxCpuRunResult run_result = {0};
    QemuCxbxCpu *cpu = NULL;
    uint8_t *page;
    int result;

    if (argc != 2) {
        fprintf(stderr, "usage: %s qemu-cxbx-i386.dll\n", argv[0]);
        return 2;
    }
    page = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!page) {
        return 11;
    }
    memcpy(page, (const uint8_t[]){0xb8, 0x78, 0x56, 0x34, 0x12, 0xf4}, 6);
    module = LoadLibraryA(argv[1]);
    if (!module) {
        fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
        return 3;
    }

    LOAD_API(module, qemu_cxbx_cpu_get_api_version);
    LOAD_API(module, qemu_cxbx_cpu_create);
    LOAD_API(module, qemu_cxbx_cpu_destroy);
    LOAD_API(module, qemu_cxbx_cpu_map_memory);
    LOAD_API(module, qemu_cxbx_cpu_set_registers);
    LOAD_API(module, qemu_cxbx_cpu_get_registers);
    LOAD_API(module, qemu_cxbx_cpu_run);
    if (!qemu_cxbx_cpu_get_api_version || !qemu_cxbx_cpu_create ||
        !qemu_cxbx_cpu_destroy || !qemu_cxbx_cpu_map_memory ||
        !qemu_cxbx_cpu_set_registers || !qemu_cxbx_cpu_get_registers ||
        !qemu_cxbx_cpu_run) {
        fprintf(stderr, "backend ABI export is missing\n");
        return 4;
    }
    if (qemu_cxbx_cpu_get_api_version() != QEMU_CXBX_CPU_ABI_VERSION) {
        fprintf(stderr, "backend ABI version mismatch\n");
        return 5;
    }

    config.struct_size = sizeof(config);
    config.version = QEMU_CXBX_CPU_CONFIG_VERSION;
    result = qemu_cxbx_cpu_create(&config, &cpu);
    if (result != QEMU_CXBX_CPU_OK) {
        fprintf(stderr, "create failed: %d\n", result);
        return 6;
    }
    result = qemu_cxbx_cpu_map_memory(cpu, 0x10000, 4096, page,
        QEMU_CXBX_CPU_MEMORY_READ | QEMU_CXBX_CPU_MEMORY_WRITE |
        QEMU_CXBX_CPU_MEMORY_EXECUTE | QEMU_CXBX_CPU_MEMORY_HOST_POINTER);
    if (result != QEMU_CXBX_CPU_OK) {
        fprintf(stderr, "map failed: %d\n", result);
        return 7;
    }

    registers.struct_size = sizeof(registers);
    registers.version = QEMU_CXBX_CPU_REGISTERS_VERSION;
    registers.eip = 0x10000;
    registers.esp = 0x10ff0;
    registers.eflags = 0x202;
    registers.cs = registers.ds = registers.es = registers.ss = 0x10;
    result = qemu_cxbx_cpu_set_registers(cpu, &registers);
    if (result != QEMU_CXBX_CPU_OK) {
        fprintf(stderr, "set registers failed: %d\n", result);
        return 8;
    }

    run_result.struct_size = sizeof(run_result);
    run_result.version = QEMU_CXBX_CPU_RUN_RESULT_VERSION;
    for (unsigned attempt = 0; attempt != 16; ++attempt) {
        result = qemu_cxbx_cpu_run(cpu, &run_result);
        if (result != QEMU_CXBX_CPU_OK) {
            fprintf(stderr, "run failed: %d\n", result);
            return 9;
        }
        if (run_result.reason != QEMU_CXBX_CPU_RUN_STOPPED) {
            break;
        }
    }
    result = qemu_cxbx_cpu_get_registers(cpu, &registers);
    if (result != QEMU_CXBX_CPU_OK || registers.eax != 0x12345678) {
        fprintf(stderr, "register result failed: result=%d reason=%u vector=%u "
                "eax=%08lx eip=%08lx\n", result, (unsigned)run_result.reason,
                (unsigned)run_result.exception_vector,
                (unsigned long)registers.eax, (unsigned long)registers.eip);
        return 10;
    }
    printf("ABI=%08lx reason=%u eax=%08lx eip=%08lx\n",
           (unsigned long)qemu_cxbx_cpu_get_api_version(),
           (unsigned)run_result.reason, (unsigned long)registers.eax,
           (unsigned long)registers.eip);
    qemu_cxbx_cpu_destroy(cpu);
    FreeLibrary(module);
    return 0;
}
