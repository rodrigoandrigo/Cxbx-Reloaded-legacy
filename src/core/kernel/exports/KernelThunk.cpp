// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
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
// *  You should have received a copy of the GNU General Public License
// *  along with this program; see the file COPYING.
// *  If not, write to the Free Software Foundation, Inc.,
// *  59 Temple Place - Suite 330, Bostom, MA 02111-1307, USA.
// *
// *  (c) 2002-2003 Aaron Robinson <caustik@caustik.com>
// *
// *  All rights reserved
// *
// ******************************************************************


#include <core\kernel\exports\xboxkrnl.h>
#include "Cxbx.h" // For CxbxKrnl_KernelThunkTable
#include "core\kernel\init\CxbxKrnl.h" // For UINT

#define FUNC(f) f
#define VARIABLE(v) v

#define DEVKIT // developer kit only functions
#define PROFILING // private kernel profiling functions
// A.k.a. _XBOX_ENABLE_PROFILING

// Kernel API availability flags per system type
#define KAPI_RETAIL  (1 << 0)
#define KAPI_DEVKIT  (1 << 1)
#define KAPI_CHIHIRO (1 << 2)
#define KAPI_ALL     (KAPI_RETAIL | KAPI_DEVKIT | KAPI_CHIHIRO)

// Returns the system availability flags for a given kernel thunk ordinal.
// On real hardware, the retail/chihiro kernel exports ordinals 1-366.
// The debug kernel additionally exports ordinals 367-378.
uint8_t CxbxKrnl_KernelThunkAvailability(int ordinal)
{
	if (ordinal >= 1 && ordinal <= 366) return KAPI_ALL;
	if (ordinal >= 367 && ordinal <= 378) return KAPI_DEVKIT;
	return 0; // ordinal 0 or out of range
}

// Returns the KAPI flag corresponding to the current emulated system
uint8_t CxbxKrnl_GetCurrentSystemFlag()
{
	if (g_bIsDevKit) return KAPI_DEVKIT;
	if (g_bIsChihiro) return KAPI_CHIHIRO;
	return KAPI_RETAIL;
}

bool CxbxKrnl_KernelThunkIsData(uint32_t ordinal)
{
	switch (ordinal) {
	case 16: case 22: case 30: case 31:
	case 40: case 41: case 42:
	case 64: case 70: case 71:
	case 88: case 89: case 102: case 120:
	case 154: case 156: case 157: case 162: case 164:
	case 240: case 245: case 249: case 259:
	case 321: case 322: case 323: case 324: case 325: case 326:
	case 353: case 354: case 355: case 356: case 357:
		return true;
	default:
		return false;
	}
}

// kernel thunk table
// Note : Names that collide with other symbols, use the KRNL() macro.
uintptr_t CxbxKrnl_KernelThunkTable[379] =
{
	(uintptr_t)FUNC(xbox::zeroptr),                                 // 0x0000 (0) "Undefined", this function doesn't exist
	(uintptr_t)FUNC(&xbox::AvGetSavedDataAddress),                  // 0x0001 (1)
	(uintptr_t)FUNC(&xbox::AvSendTVEncoderOption),                   // 0x0002 (2)
	(uintptr_t)FUNC(&xbox::AvSetDisplayMode),                        // 0x0003 (3)
	(uintptr_t)FUNC(&xbox::AvSetSavedDataAddress),                   // 0x0004 (4)
	(uintptr_t)FUNC(&xbox::DbgBreakPoint),                           // 0x0005 (5)
	(uintptr_t)FUNC(&xbox::DbgBreakPointWithStatus),                 // 0x0006 (6)
	(uintptr_t)FUNC(&xbox::DbgLoadImageSymbols),                     // 0x0007 (7) DEVKIT
	(uintptr_t)FUNC(&xbox::DbgPrint),                                // 0x0008 (8)
	(uintptr_t)FUNC(&xbox::HalReadSMCTrayState),                     // 0x0009 (9)
	(uintptr_t)FUNC(&xbox::DbgPrompt),                               // 0x000A (10)
	(uintptr_t)FUNC(&xbox::DbgUnLoadImageSymbols),                   // 0x000B (11) DEVKIT
	(uintptr_t)FUNC(&xbox::ExAcquireReadWriteLockExclusive),         // 0x000C (12)
	(uintptr_t)FUNC(&xbox::ExAcquireReadWriteLockShared),            // 0x000D (13)
	(uintptr_t)FUNC(&xbox::ExAllocatePool),                          // 0x000E (14)
	(uintptr_t)FUNC(&xbox::ExAllocatePoolWithTag),                   // 0x000F (15)
	(uintptr_t)VARIABLE(&xbox::ExEventObjectType),                   // 0x0010 (16)
	(uintptr_t)FUNC(&xbox::ExFreePool),                              // 0x0011 (17)
	(uintptr_t)FUNC(&xbox::ExInitializeReadWriteLock),               // 0x0012 (18)
	(uintptr_t)FUNC(&xbox::ExInterlockedAddLargeInteger),            // 0x0013 (19)
	(uintptr_t)FUNC(&xbox::ExInterlockedAddLargeStatistic),          // 0x0014 (20)
	(uintptr_t)FUNC(&xbox::ExInterlockedCompareExchange64),          // 0x0015 (21)
	(uintptr_t)VARIABLE(&xbox::ExMutantObjectType),                  // 0x0016 (22)
	(uintptr_t)FUNC(&xbox::ExQueryPoolBlockSize),                    // 0x0017 (23)
	(uintptr_t)FUNC(&xbox::ExQueryNonVolatileSetting),               // 0x0018 (24)
	(uintptr_t)FUNC(&xbox::ExReadWriteRefurbInfo),                   // 0x0019 (25)
	(uintptr_t)FUNC(&xbox::ExRaiseException),                        // 0x001A (26)
	(uintptr_t)FUNC(&xbox::ExRaiseStatus),                           // 0x001B (27)
	(uintptr_t)FUNC(&xbox::ExReleaseReadWriteLock),                  // 0x001C (28)
	(uintptr_t)FUNC(&xbox::ExSaveNonVolatileSetting),                // 0x001D (29)
	(uintptr_t)VARIABLE(&xbox::ExSemaphoreObjectType),               // 0x001E (30)
	(uintptr_t)VARIABLE(&xbox::ExTimerObjectType),                   // 0x001F (31)
	(uintptr_t)FUNC(&xbox::ExfInterlockedInsertHeadList),            // 0x0020 (32)
	(uintptr_t)FUNC(&xbox::ExfInterlockedInsertTailList),            // 0x0021 (33)
	(uintptr_t)FUNC(&xbox::ExfInterlockedRemoveHeadList),            // 0x0022 (34)
	(uintptr_t)FUNC(&xbox::FscGetCacheSize),                         // 0x0023 (35)
	(uintptr_t)FUNC(&xbox::FscInvalidateIdleBlocks),                 // 0x0024 (36)
	(uintptr_t)FUNC(&xbox::FscSetCacheSize),                         // 0x0025 (37)
	(uintptr_t)FUNC(&xbox::HalClearSoftwareInterrupt),               // 0x0026 (38)
	(uintptr_t)FUNC(&xbox::HalDisableSystemInterrupt),               // 0x0027 (39)
	(uintptr_t)VARIABLE(&xbox::HalDiskCachePartitionCount),          // 0x0028 (40)  A.k.a. "IdexDiskPartitionPrefixBuffer"
	(uintptr_t)VARIABLE(&xbox::HalDiskModelNumber),                  // 0x0029 (41)
	(uintptr_t)VARIABLE(&xbox::HalDiskSerialNumber),                 // 0x002A (42)
	(uintptr_t)FUNC(&xbox::HalEnableSystemInterrupt),                // 0x002B (43)
	(uintptr_t)FUNC(&xbox::HalGetInterruptVector),                   // 0x002C (44)
	(uintptr_t)FUNC(&xbox::HalReadSMBusValue),                       // 0x002D (45)
	(uintptr_t)FUNC(&xbox::HalReadWritePCISpace),                    // 0x002E (46)
	(uintptr_t)FUNC(&xbox::HalRegisterShutdownNotification),         // 0x002F (47)
	(uintptr_t)FUNC(&xbox::HalRequestSoftwareInterrupt),             // 0x0030 (48)
	(uintptr_t)FUNC(&xbox::HalReturnToFirmware),                     // 0x0031 (49)
	(uintptr_t)FUNC(&xbox::HalWriteSMBusValue),                      // 0x0032 (50)
	(uintptr_t)FUNC(&xbox::KRNL(InterlockedCompareExchange)),        // 0x0033 (51)
	(uintptr_t)FUNC(&xbox::KRNL(InterlockedDecrement)),              // 0x0034 (52)
	(uintptr_t)FUNC(&xbox::KRNL(InterlockedIncrement)),              // 0x0035 (53)
	(uintptr_t)FUNC(&xbox::KRNL(InterlockedExchange)),               // 0x0036 (54)
	(uintptr_t)FUNC(&xbox::KRNL(InterlockedExchangeAdd)),            // 0x0037 (55)
	(uintptr_t)FUNC(&xbox::KRNL(InterlockedFlushSList)),             // 0x0038 (56)
	(uintptr_t)FUNC(&xbox::KRNL(InterlockedPopEntrySList)),          // 0x0039 (57)
	(uintptr_t)FUNC(&xbox::KRNL(InterlockedPushEntrySList)),         // 0x003A (58)
	(uintptr_t)FUNC(&xbox::IoAllocateIrp),                           // 0x003B (59)
	(uintptr_t)FUNC(&xbox::IoBuildAsynchronousFsdRequest),           // 0x003C (60)
	(uintptr_t)FUNC(&xbox::IoBuildDeviceIoControlRequest),           // 0x003D (61)
	(uintptr_t)FUNC(&xbox::IoBuildSynchronousFsdRequest),            // 0x003E (62)
	(uintptr_t)FUNC(&xbox::IoCheckShareAccess),                      // 0x003F (63)
	(uintptr_t)VARIABLE(&xbox::IoCompletionObjectType),              // 0x0040 (64)
	(uintptr_t)FUNC(&xbox::IoCreateDevice),                          // 0x0041 (65)
	(uintptr_t)FUNC(&xbox::IoCreateFile),                            // 0x0042 (66)
	(uintptr_t)FUNC(&xbox::IoCreateSymbolicLink),                    // 0x0043 (67)
	(uintptr_t)FUNC(&xbox::IoDeleteDevice),                          // 0x0044 (68)
	(uintptr_t)FUNC(&xbox::IoDeleteSymbolicLink),                    // 0x0045 (69)
	(uintptr_t)VARIABLE(&xbox::IoDeviceObjectType),                  // 0x0046 (70)
	(uintptr_t)VARIABLE(&xbox::IoFileObjectType),                    // 0x0047 (71)
	(uintptr_t)FUNC(&xbox::IoFreeIrp),                               // 0x0048 (72)
	(uintptr_t)FUNC(&xbox::IoInitializeIrp),                         // 0x0049 (73)
	(uintptr_t)FUNC(&xbox::IoInvalidDeviceRequest),                  // 0x004A (74)
	(uintptr_t)FUNC(&xbox::IoQueryFileInformation),                  // 0x004B (75)
	(uintptr_t)FUNC(&xbox::IoQueryVolumeInformation),                // 0x004C (76)
	(uintptr_t)FUNC(&xbox::IoQueueThreadIrp),                        // 0x004D (77)
	(uintptr_t)FUNC(&xbox::IoRemoveShareAccess),                     // 0x004E (78)
	(uintptr_t)FUNC(&xbox::IoSetIoCompletion),                       // 0x004F (79)
	(uintptr_t)FUNC(&xbox::IoSetShareAccess),                        // 0x0050 (80)
	(uintptr_t)FUNC(&xbox::IoStartNextPacket),                       // 0x0051 (81)
	(uintptr_t)FUNC(&xbox::IoStartNextPacketByKey),                  // 0x0052 (82)
	(uintptr_t)FUNC(&xbox::IoStartPacket),                           // 0x0053 (83)
	(uintptr_t)FUNC(&xbox::IoSynchronousDeviceIoControlRequest),     // 0x0054 (84)
	(uintptr_t)FUNC(&xbox::IoSynchronousFsdRequest),                 // 0x0055 (85)
	(uintptr_t)FUNC(&xbox::IofCallDriver),                           // 0x0056 (86)
	(uintptr_t)FUNC(&xbox::IofCompleteRequest),                      // 0x0057 (87)
	(uintptr_t)VARIABLE(&xbox::KdDebuggerEnabled),                   // 0x0058 (88)
	(uintptr_t)VARIABLE(&xbox::KdDebuggerNotPresent),                // 0x0059 (89)
	(uintptr_t)FUNC(&xbox::IoDismountVolume),                        // 0x005A (90)
	(uintptr_t)FUNC(&xbox::IoDismountVolumeByName),                  // 0x005B (91)
	(uintptr_t)FUNC(&xbox::KeAlertResumeThread),                     // 0x005C (92)
	(uintptr_t)FUNC(&xbox::KeAlertThread),                           // 0x005D (93)
	(uintptr_t)FUNC(&xbox::KeBoostPriorityThread),                   // 0x005E (94)
	(uintptr_t)FUNC(&xbox::KeBugCheck),                              // 0x005F (95)
	(uintptr_t)FUNC(&xbox::KeBugCheckEx),                            // 0x0060 (96)
	(uintptr_t)FUNC(&xbox::KeCancelTimer),                           // 0x0061 (97)
	(uintptr_t)FUNC(&xbox::KeConnectInterrupt),                      // 0x0062 (98)
	(uintptr_t)FUNC(&xbox::KeDelayExecutionThread),                  // 0x0063 (99)
	(uintptr_t)FUNC(&xbox::KeDisconnectInterrupt),                   // 0x0064 (100
	(uintptr_t)FUNC(&xbox::KeEnterCriticalRegion),                   // 0x0065 (101)
	(uintptr_t)VARIABLE(&xbox::MmGlobalData),                        // 0x0066 (102)
	(uintptr_t)FUNC(&xbox::KeGetCurrentIrql),                        // 0x0067 (103)
	(uintptr_t)FUNC(&xbox::KeGetCurrentThread),                      // 0x0068 (104)
	(uintptr_t)FUNC(&xbox::KeInitializeApc),                         // 0x0069 (105)
	(uintptr_t)FUNC(&xbox::KeInitializeDeviceQueue),                 // 0x006A (106)
	(uintptr_t)FUNC(&xbox::KeInitializeDpc),                         // 0x006B (107)
	(uintptr_t)FUNC(&xbox::KeInitializeEvent),                       // 0x006C (108)
	(uintptr_t)FUNC(&xbox::KeInitializeInterrupt),                   // 0x006D (109)
	(uintptr_t)FUNC(&xbox::KeInitializeMutant),                      // 0x006E (110)
	(uintptr_t)FUNC(&xbox::KeInitializeQueue),                       // 0x006F (111)
	(uintptr_t)FUNC(&xbox::KeInitializeSemaphore),                   // 0x0070 (112)
	(uintptr_t)FUNC(&xbox::KeInitializeTimerEx),                     // 0x0071 (113)
	(uintptr_t)FUNC(&xbox::KeInsertByKeyDeviceQueue),                // 0x0072 (114)
	(uintptr_t)FUNC(&xbox::KeInsertDeviceQueue),                     // 0x0073 (115)
	(uintptr_t)FUNC(&xbox::KeInsertHeadQueue),                       // 0x0074 (116)
	(uintptr_t)FUNC(&xbox::KeInsertQueue),                           // 0x0075 (117)
	(uintptr_t)FUNC(&xbox::KeInsertQueueApc),                        // 0x0076 (118)
	(uintptr_t)FUNC(&xbox::KeInsertQueueDpc),                        // 0x0077 (119)
	(uintptr_t)VARIABLE(&xbox::KeInterruptTime),                     // 0x0078 (120) KeInterruptTime
	(uintptr_t)FUNC(&xbox::KeIsExecutingDpc),                        // 0x0079 (121)
	(uintptr_t)FUNC(&xbox::KeLeaveCriticalRegion),                   // 0x007A (122)
	(uintptr_t)FUNC(&xbox::KePulseEvent),                            // 0x007B (123)
	(uintptr_t)FUNC(&xbox::KeQueryBasePriorityThread),               // 0x007C (124)
	(uintptr_t)FUNC(&xbox::KeQueryInterruptTime),                    // 0x007D (125)
	(uintptr_t)FUNC(&xbox::KeQueryPerformanceCounter),               // 0x007E (126)
	(uintptr_t)FUNC(&xbox::KeQueryPerformanceFrequency),             // 0x007F (127)
	(uintptr_t)FUNC(&xbox::KeQuerySystemTime),                       // 0x0080 (128)
	(uintptr_t)FUNC(&xbox::KeRaiseIrqlToDpcLevel),                   // 0x0081 (129)
	(uintptr_t)FUNC(&xbox::KeRaiseIrqlToSynchLevel),                 // 0x0082 (130)
	(uintptr_t)FUNC(&xbox::KeReleaseMutant),                         // 0x0083 (131)
	(uintptr_t)FUNC(&xbox::KeReleaseSemaphore),                      // 0x0084 (132)
	(uintptr_t)FUNC(&xbox::KeRemoveByKeyDeviceQueue),                // 0x0085 (133)
	(uintptr_t)FUNC(&xbox::KeRemoveDeviceQueue),                     // 0x0086 (134)
	(uintptr_t)FUNC(&xbox::KeRemoveEntryDeviceQueue),                // 0x0087 (135)
	(uintptr_t)FUNC(&xbox::KeRemoveQueue),                           // 0x0088 (136)
	(uintptr_t)FUNC(&xbox::KeRemoveQueueDpc),                        // 0x0089 (137)
	(uintptr_t)FUNC(&xbox::KeResetEvent),                            // 0x008A (138)
	(uintptr_t)FUNC(&xbox::KeRestoreFloatingPointState),             // 0x008B (139)
	(uintptr_t)FUNC(&xbox::KeResumeThread),                          // 0x008C (140)
	(uintptr_t)FUNC(&xbox::KeRundownQueue),                          // 0x008D (141)
	(uintptr_t)FUNC(&xbox::KeSaveFloatingPointState),                // 0x008E (142)
	(uintptr_t)FUNC(&xbox::KeSetBasePriorityThread),                 // 0x008F (143)
	(uintptr_t)FUNC(&xbox::KeSetDisableBoostThread),                 // 0x0090 (144)
	(uintptr_t)FUNC(&xbox::KeSetEvent),                              // 0x0091 (145)
	(uintptr_t)FUNC(&xbox::KeSetEventBoostPriority),                 // 0x0092 (146)
	(uintptr_t)FUNC(&xbox::KeSetPriorityProcess),                    // 0x0093 (147)
	(uintptr_t)FUNC(&xbox::KeSetPriorityThread),                     // 0x0094 (148)
	(uintptr_t)FUNC(&xbox::KeSetTimer),                              // 0x0095 (149)
	(uintptr_t)FUNC(&xbox::KeSetTimerEx),                            // 0x0096 (150)
	(uintptr_t)FUNC(&xbox::KeStallExecutionProcessor),               // 0x0097 (151)
	(uintptr_t)FUNC(&xbox::KeSuspendThread),                         // 0x0098 (152)
	(uintptr_t)FUNC(&xbox::KeSynchronizeExecution),                  // 0x0099 (153)
	(uintptr_t)VARIABLE(&xbox::KeSystemTime),                        // 0x009A (154) KeSystemTime
	(uintptr_t)FUNC(&xbox::KeTestAlertThread),                       // 0x009B (155)
	(uintptr_t)VARIABLE(&xbox::KeTickCount),                         // 0x009C (156)
	(uintptr_t)VARIABLE(&xbox::KeTimeIncrement),                     // 0x009D (157)
	(uintptr_t)FUNC(&xbox::KeWaitForMultipleObjects),                // 0x009E (158)
	(uintptr_t)FUNC(&xbox::KeWaitForSingleObject),                   // 0x009F (159)
	(uintptr_t)FUNC(&xbox::KfRaiseIrql),                             // 0x00A0 (160)
	(uintptr_t)FUNC(&xbox::KfLowerIrql),                             // 0x00A1 (161)
	(uintptr_t)VARIABLE(&xbox::KiBugCheckData),                      // 0x00A2 (162)
	(uintptr_t)FUNC(&xbox::KiUnlockDispatcherDatabase),              // 0x00A3 (163)
	(uintptr_t)VARIABLE(&xbox::LaunchDataPage),                      // 0x00A4 (164)
	(uintptr_t)FUNC(&xbox::MmAllocateContiguousMemory),              // 0x00A5 (165)
	(uintptr_t)FUNC(&xbox::MmAllocateContiguousMemoryEx),            // 0x00A6 (166)
	(uintptr_t)FUNC(&xbox::MmAllocateSystemMemory),                  // 0x00A7 (167)
	(uintptr_t)FUNC(&xbox::MmClaimGpuInstanceMemory),                // 0x00A8 (168)
	(uintptr_t)FUNC(&xbox::MmCreateKernelStack),                     // 0x00A9 (169)
	(uintptr_t)FUNC(&xbox::MmDeleteKernelStack),                     // 0x00AA (170)
	(uintptr_t)FUNC(&xbox::MmFreeContiguousMemory),                  // 0x00AB (171)
	(uintptr_t)FUNC(&xbox::MmFreeSystemMemory),                      // 0x00AC (172)
	(uintptr_t)FUNC(&xbox::MmGetPhysicalAddress),                    // 0x00AD (173)
	(uintptr_t)FUNC(&xbox::MmIsAddressValid),                        // 0x00AE (174)
	(uintptr_t)FUNC(&xbox::MmLockUnlockBufferPages),                 // 0x00AF (175)
	(uintptr_t)FUNC(&xbox::MmLockUnlockPhysicalPage),                // 0x00B0 (176)
	(uintptr_t)FUNC(&xbox::MmMapIoSpace),                            // 0x00B1 (177)
	(uintptr_t)FUNC(&xbox::MmPersistContiguousMemory),               // 0x00B2 (178)
	(uintptr_t)FUNC(&xbox::MmQueryAddressProtect),                   // 0x00B3 (179)
	(uintptr_t)FUNC(&xbox::MmQueryAllocationSize),                   // 0x00B4 (180)
	(uintptr_t)FUNC(&xbox::MmQueryStatistics),                       // 0x00B5 (181)
	(uintptr_t)FUNC(&xbox::MmSetAddressProtect),                     // 0x00B6 (182)
	(uintptr_t)FUNC(&xbox::MmUnmapIoSpace),                          // 0x00B7 (183)
	(uintptr_t)FUNC(&xbox::NtAllocateVirtualMemory),                 // 0x00B8 (184)
	(uintptr_t)FUNC(&xbox::NtCancelTimer),                           // 0x00B9 (185)
	(uintptr_t)FUNC(&xbox::NtClearEvent),                            // 0x00BA (186)
	(uintptr_t)FUNC(&xbox::NtClose),                                 // 0x00BB (187)
	(uintptr_t)FUNC(&xbox::NtCreateDirectoryObject),                 // 0x00BC (188)
	(uintptr_t)FUNC(&xbox::NtCreateEvent),                           // 0x00BD (189)
	(uintptr_t)FUNC(&xbox::NtCreateFile),                            // 0x00BE (190)
	(uintptr_t)FUNC(&xbox::NtCreateIoCompletion),                    // 0x00BF (191)
	(uintptr_t)FUNC(&xbox::NtCreateMutant),                          // 0x00C0 (192)
	(uintptr_t)FUNC(&xbox::NtCreateSemaphore),                       // 0x00C1 (193)
	(uintptr_t)FUNC(&xbox::NtCreateTimer),                           // 0x00C2 (194)
	(uintptr_t)FUNC(&xbox::NtDeleteFile),                            // 0x00C3 (195)
	(uintptr_t)FUNC(&xbox::NtDeviceIoControlFile),                   // 0x00C4 (196)
	(uintptr_t)FUNC(&xbox::NtDuplicateObject),                       // 0x00C5 (197)
	(uintptr_t)FUNC(&xbox::NtFlushBuffersFile),                      // 0x00C6 (198)
	(uintptr_t)FUNC(&xbox::NtFreeVirtualMemory),                     // 0x00C7 (199)
	(uintptr_t)FUNC(&xbox::NtFsControlFile),                         // 0x00C8 (200)
	(uintptr_t)FUNC(&xbox::NtOpenDirectoryObject),                   // 0x00C9 (201)
	(uintptr_t)FUNC(&xbox::NtOpenFile),                              // 0x00CA (202)
	(uintptr_t)FUNC(&xbox::NtOpenSymbolicLinkObject),                // 0x00CB (203)
	(uintptr_t)FUNC(&xbox::NtProtectVirtualMemory),                  // 0x00CC (204)
	(uintptr_t)FUNC(&xbox::NtPulseEvent),                            // 0x00CD (205)
	(uintptr_t)FUNC(&xbox::NtQueueApcThread),                        // 0x00CE (206)
	(uintptr_t)FUNC(&xbox::NtQueryDirectoryFile),                    // 0x00CF (207)
	(uintptr_t)FUNC(&xbox::NtQueryDirectoryObject),                  // 0x00D0 (208)
	(uintptr_t)FUNC(&xbox::NtQueryEvent),                            // 0x00D1 (209)
	(uintptr_t)FUNC(&xbox::NtQueryFullAttributesFile),               // 0x00D2 (210)
	(uintptr_t)FUNC(&xbox::NtQueryInformationFile),                  // 0x00D3 (211)
	(uintptr_t)FUNC(&xbox::NtQueryIoCompletion),                     // 0x00D4 (212)
	(uintptr_t)FUNC(&xbox::NtQueryMutant),                           // 0x00D5 (213)
	(uintptr_t)FUNC(&xbox::NtQuerySemaphore),                        // 0x00D6 (214)
	(uintptr_t)FUNC(&xbox::NtQuerySymbolicLinkObject),               // 0x00D7 (215)
	(uintptr_t)FUNC(&xbox::NtQueryTimer),                            // 0x00D8 (216)
	(uintptr_t)FUNC(&xbox::NtQueryVirtualMemory),                    // 0x00D9 (217)
	(uintptr_t)FUNC(&xbox::NtQueryVolumeInformationFile),            // 0x00DA (218)
	(uintptr_t)FUNC(&xbox::NtReadFile),                              // 0x00DB (219)
	(uintptr_t)FUNC(&xbox::NtReadFileScatter),                       // 0x00DC (220)
	(uintptr_t)FUNC(&xbox::NtReleaseMutant),                         // 0x00DD (221)
	(uintptr_t)FUNC(&xbox::NtReleaseSemaphore),                      // 0x00DE (222)
	(uintptr_t)FUNC(&xbox::NtRemoveIoCompletion),                    // 0x00DF (223)
	(uintptr_t)FUNC(&xbox::NtResumeThread),                          // 0x00E0 (224)
	(uintptr_t)FUNC(&xbox::NtSetEvent),                              // 0x00E1 (225)
	(uintptr_t)FUNC(&xbox::NtSetInformationFile),                    // 0x00E2 (226)
	(uintptr_t)FUNC(&xbox::NtSetIoCompletion),                       // 0x00E3 (227)
	(uintptr_t)FUNC(&xbox::NtSetSystemTime),                         // 0x00E4 (228)
	(uintptr_t)FUNC(&xbox::NtSetTimerEx),                            // 0x00E5 (229)
	(uintptr_t)FUNC(&xbox::NtSignalAndWaitForSingleObjectEx),        // 0x00E6 (230)
	(uintptr_t)FUNC(&xbox::NtSuspendThread),                         // 0x00E7 (231)
	(uintptr_t)FUNC(&xbox::NtUserIoApcDispatcher),                   // 0x00E8 (232)
	(uintptr_t)FUNC(&xbox::NtWaitForSingleObject),                   // 0x00E9 (233)
	(uintptr_t)FUNC(&xbox::NtWaitForSingleObjectEx),                 // 0x00EA (234)
	(uintptr_t)FUNC(&xbox::NtWaitForMultipleObjectsEx),              // 0x00EB (235)
	(uintptr_t)FUNC(&xbox::NtWriteFile),                             // 0x00EC (236)
	(uintptr_t)FUNC(&xbox::NtWriteFileGather),                       // 0x00ED (237)
	(uintptr_t)FUNC(&xbox::NtYieldExecution),                        // 0x00EE (238)
	(uintptr_t)FUNC(&xbox::ObCreateObject),                          // 0x00EF (239)
	(uintptr_t)VARIABLE(&xbox::ObDirectoryObjectType),               // 0x00F0 (240)
	(uintptr_t)FUNC(&xbox::ObInsertObject),                          // 0x00F1 (241)
	(uintptr_t)FUNC(&xbox::ObMakeTemporaryObject),                   // 0x00F2 (242) 
	(uintptr_t)FUNC(&xbox::ObOpenObjectByName),                      // 0x00F3 (243)
	(uintptr_t)FUNC(&xbox::ObOpenObjectByPointer),                   // 0x00F4 (244)
	(uintptr_t)VARIABLE(&xbox::ObpObjectHandleTable),                // 0x00F5 (245)
	(uintptr_t)FUNC(&xbox::ObReferenceObjectByHandle),               // 0x00F6 (246)
	(uintptr_t)FUNC(&xbox::ObReferenceObjectByName),                 // 0x00F7 (247)
	(uintptr_t)FUNC(&xbox::ObReferenceObjectByPointer),              // 0x00F8 (248)
	(uintptr_t)VARIABLE(&xbox::ObSymbolicLinkObjectType),            // 0x00F9 (249)
	(uintptr_t)FUNC(&xbox::ObfDereferenceObject),                    // 0x00FA (250)
	(uintptr_t)FUNC(&xbox::ObfReferenceObject),                      // 0x00FB (251)
	(uintptr_t)FUNC(&xbox::PhyGetLinkState),                         // 0x00FC (252)
	(uintptr_t)FUNC(&xbox::PhyInitialize),                           // 0x00FD (253)
	(uintptr_t)FUNC(&xbox::PsCreateSystemThread),                    // 0x00FE (254)
	(uintptr_t)FUNC(&xbox::PsCreateSystemThreadEx),                  // 0x00FF (255)
	(uintptr_t)FUNC(&xbox::PsQueryStatistics),                       // 0x0100 (256)
	(uintptr_t)FUNC(&xbox::PsSetCreateThreadNotifyRoutine),          // 0x0101 (257)
	(uintptr_t)FUNC(&xbox::PsTerminateSystemThread),                 // 0x0102 (258)
	(uintptr_t)VARIABLE(&xbox::PsThreadObjectType),                  // 0x0103 (259)
	(uintptr_t)FUNC(&xbox::RtlAnsiStringToUnicodeString),            // 0x0104 (260)
	(uintptr_t)FUNC(&xbox::RtlAppendStringToString),                 // 0x0105 (261)
	(uintptr_t)FUNC(&xbox::RtlAppendUnicodeStringToString),          // 0x0106 (262)
	(uintptr_t)FUNC(&xbox::RtlAppendUnicodeToString),                // 0x0107 (263)
	(uintptr_t)FUNC(&xbox::RtlAssert),                               // 0x0108 (264)
	(uintptr_t)FUNC(&xbox::RtlCaptureContext),                       // 0x0109 (265)
	(uintptr_t)FUNC(&xbox::RtlCaptureStackBackTrace),                // 0x010A (266)
	(uintptr_t)FUNC(&xbox::RtlCharToInteger),                        // 0x010B (267)
	(uintptr_t)FUNC(&xbox::RtlCompareMemory),                        // 0x010C (268)
	(uintptr_t)FUNC(&xbox::RtlCompareMemoryUlong),                   // 0x010D (269)
	(uintptr_t)FUNC(&xbox::RtlCompareString),                        // 0x010E (270)
	(uintptr_t)FUNC(&xbox::RtlCompareUnicodeString),                 // 0x010F (271)
	(uintptr_t)FUNC(&xbox::RtlCopyString),                           // 0x0110 (272)
	(uintptr_t)FUNC(&xbox::RtlCopyUnicodeString),                    // 0x0111 (273)
	(uintptr_t)FUNC(&xbox::RtlCreateUnicodeString),                  // 0x0112 (274)
	(uintptr_t)FUNC(&xbox::RtlDowncaseUnicodeChar),                  // 0x0113 (275)
	(uintptr_t)FUNC(&xbox::RtlDowncaseUnicodeString),                // 0x0114 (276)
	(uintptr_t)FUNC(&xbox::RtlEnterCriticalSection),                 // 0x0115 (277)
	(uintptr_t)FUNC(&xbox::RtlEnterCriticalSectionAndRegion),        // 0x0116 (278)
	(uintptr_t)FUNC(&xbox::RtlEqualString),                          // 0x0117 (279)
	(uintptr_t)FUNC(&xbox::RtlEqualUnicodeString),                   // 0x0118 (280)
	(uintptr_t)FUNC(&xbox::RtlExtendedIntegerMultiply),              // 0x0119 (281)
	(uintptr_t)FUNC(&xbox::RtlExtendedLargeIntegerDivide),           // 0x011A (282)
	(uintptr_t)FUNC(&xbox::RtlExtendedMagicDivide),                  // 0x011B (283)
	(uintptr_t)FUNC(&xbox::RtlFillMemory),                           // 0x011C (284)
	(uintptr_t)FUNC(&xbox::RtlFillMemoryUlong),                      // 0x011D (285)
	(uintptr_t)FUNC(&xbox::RtlFreeAnsiString),                       // 0x011E (286)
	(uintptr_t)FUNC(&xbox::RtlFreeUnicodeString),                    // 0x011F (287)
	(uintptr_t)FUNC(&xbox::RtlGetCallersAddress),                    // 0x0120 (288)
	(uintptr_t)FUNC(&xbox::RtlInitAnsiString),                       // 0x0121 (289)
	(uintptr_t)FUNC(&xbox::RtlInitUnicodeString),                    // 0x0122 (290)
	(uintptr_t)FUNC(&xbox::RtlInitializeCriticalSection),            // 0x0123 (291)
	(uintptr_t)FUNC(&xbox::RtlIntegerToChar),                        // 0x0124 (292)
	(uintptr_t)FUNC(&xbox::RtlIntegerToUnicodeString),               // 0x0125 (293)
	(uintptr_t)FUNC(&xbox::RtlLeaveCriticalSection),                 // 0x0126 (294)
	(uintptr_t)FUNC(&xbox::RtlLeaveCriticalSectionAndRegion),        // 0x0127 (295)
	(uintptr_t)FUNC(&xbox::RtlLowerChar),                            // 0x0128 (296)
	(uintptr_t)FUNC(&xbox::RtlMapGenericMask),                       // 0x0129 (297)
	(uintptr_t)FUNC(&xbox::RtlMoveMemory),                           // 0x012A (298)
	(uintptr_t)FUNC(&xbox::RtlMultiByteToUnicodeN),                  // 0x012B (299)
	(uintptr_t)FUNC(&xbox::RtlMultiByteToUnicodeSize),               // 0x012C (300)
	(uintptr_t)FUNC(&xbox::RtlNtStatusToDosError),                   // 0x012D (301)
	(uintptr_t)FUNC(&xbox::RtlRaiseException),                       // 0x012E (302)
	(uintptr_t)FUNC(&xbox::RtlRaiseStatus),                          // 0x012F (303)
	(uintptr_t)FUNC(&xbox::RtlTimeFieldsToTime),                     // 0x0130 (304)
	(uintptr_t)FUNC(&xbox::RtlTimeToTimeFields),                     // 0x0131 (305)
	(uintptr_t)FUNC(&xbox::RtlTryEnterCriticalSection),              // 0x0132 (306)
	(uintptr_t)FUNC(&xbox::RtlUlongByteSwap),                        // 0x0133 (307)
	(uintptr_t)FUNC(&xbox::RtlUnicodeStringToAnsiString),            // 0x0134 (308)
	(uintptr_t)FUNC(&xbox::RtlUnicodeStringToInteger),               // 0x0135 (309)
	(uintptr_t)FUNC(&xbox::RtlUnicodeToMultiByteN),                  // 0x0136 (310)
	(uintptr_t)FUNC(&xbox::RtlUnicodeToMultiByteSize),               // 0x0137 (311)
	(uintptr_t)FUNC(&xbox::RtlUnwind),                               // 0x0138 (312)
	(uintptr_t)FUNC(&xbox::RtlUpcaseUnicodeChar),                    // 0x0139 (313)
	(uintptr_t)FUNC(&xbox::RtlUpcaseUnicodeString),                  // 0x013A (314)
	(uintptr_t)FUNC(&xbox::RtlUpcaseUnicodeToMultiByteN),            // 0x013B (315)
	(uintptr_t)FUNC(&xbox::RtlUpperChar),                            // 0x013C (316)
	(uintptr_t)FUNC(&xbox::RtlUpperString),                          // 0x013D (317)
	(uintptr_t)FUNC(&xbox::RtlUshortByteSwap),                       // 0x013E (318)
	(uintptr_t)FUNC(&xbox::RtlWalkFrameChain),                       // 0x013F (319)
	(uintptr_t)FUNC(&xbox::RtlZeroMemory),                           // 0x0140 (320)
	(uintptr_t)VARIABLE(&xbox::XboxEEPROMKey),                       // 0x0141 (321)
	(uintptr_t)VARIABLE(&xbox::XboxHardwareInfo),                    // 0x0142 (322)
	(uintptr_t)VARIABLE(&xbox::XboxHDKey),                           // 0x0143 (323)
	(uintptr_t)VARIABLE(&xbox::XboxKrnlVersion),                     // 0x0144 (324)
	(uintptr_t)VARIABLE(&xbox::XboxSignatureKey),                    // 0x0145 (325)
	(uintptr_t)VARIABLE(&xbox::XeImageFileName),                     // 0x0146 (326)
	(uintptr_t)FUNC(&xbox::XeLoadSection),                           // 0x0147 (327)
	(uintptr_t)FUNC(&xbox::XeUnloadSection),                         // 0x0148 (328)
	(uintptr_t)FUNC(&xbox::READ_PORT_BUFFER_UCHAR),                  // 0x0149 (329)
	(uintptr_t)FUNC(&xbox::READ_PORT_BUFFER_USHORT),                 // 0x014A (330)
	(uintptr_t)FUNC(&xbox::READ_PORT_BUFFER_ULONG),                  // 0x014B (331)
	(uintptr_t)FUNC(&xbox::WRITE_PORT_BUFFER_UCHAR),                 // 0x014C (332)
	(uintptr_t)FUNC(&xbox::WRITE_PORT_BUFFER_USHORT),                // 0x014D (333)
	(uintptr_t)FUNC(&xbox::WRITE_PORT_BUFFER_ULONG),                 // 0x014E (334)
	(uintptr_t)FUNC(&xbox::XcSHAInit),                               // 0x014F (335)
	(uintptr_t)FUNC(&xbox::XcSHAUpdate),                             // 0x0150 (336)
	(uintptr_t)FUNC(&xbox::XcSHAFinal),                              // 0x0151 (337)
	(uintptr_t)FUNC(&xbox::XcRC4Key),                                // 0x0152 (338)
	(uintptr_t)FUNC(&xbox::XcRC4Crypt),                              // 0x0153 (339)
	(uintptr_t)FUNC(&xbox::XcHMAC),                                  // 0x0154 (340)
	(uintptr_t)FUNC(&xbox::XcPKEncPublic),                           // 0x0155 (341)
	(uintptr_t)FUNC(&xbox::XcPKDecPrivate),                          // 0x0156 (342)
	(uintptr_t)FUNC(&xbox::XcPKGetKeyLen),                           // 0x0157 (343)
	(uintptr_t)FUNC(&xbox::XcVerifyPKCS1Signature),                  // 0x0158 (344)
	(uintptr_t)FUNC(&xbox::XcModExp),                                // 0x0159 (345)
	(uintptr_t)FUNC(&xbox::XcDESKeyParity),                          // 0x015A (346)
	(uintptr_t)FUNC(&xbox::XcKeyTable),                              // 0x015B (347)
	(uintptr_t)FUNC(&xbox::XcBlockCrypt),                            // 0x015C (348)
	(uintptr_t)FUNC(&xbox::XcBlockCryptCBC),                         // 0x015D (349)
	(uintptr_t)FUNC(&xbox::XcCryptService),                          // 0x015E (350)
	(uintptr_t)FUNC(&xbox::XcUpdateCrypto),                          // 0x015F (351)
	(uintptr_t)FUNC(&xbox::RtlRip),                                  // 0x0160 (352)
	(uintptr_t)VARIABLE(&xbox::XboxLANKey),                          // 0x0161 (353)
	(uintptr_t)VARIABLE(&xbox::XboxAlternateSignatureKeys),          // 0x0162 (354)
	(uintptr_t)VARIABLE(&xbox::XePublicKeyData),                     // 0x0163 (355)
	(uintptr_t)VARIABLE(&xbox::HalBootSMCVideoMode),                 // 0x0164 (356)
	(uintptr_t)VARIABLE(&xbox::IdexChannelObject),                   // 0x0165 (357)
	(uintptr_t)FUNC(&xbox::HalIsResetOrShutdownPending),             // 0x0166 (358)
	(uintptr_t)FUNC(&xbox::IoMarkIrpMustComplete),                   // 0x0167 (359)
	(uintptr_t)FUNC(&xbox::HalInitiateShutdown),                     // 0x0168 (360)
	(uintptr_t)FUNC(&xbox::RtlSnprintf),                             // 0x0169 (361)
	(uintptr_t)FUNC(&xbox::RtlSprintf),                              // 0x016A (362)
	(uintptr_t)FUNC(&xbox::RtlVsnprintf),                            // 0x016B (363) 
	(uintptr_t)FUNC(&xbox::RtlVsprintf),                             // 0x016C (364)
	(uintptr_t)FUNC(&xbox::HalEnableSecureTrayEject),                // 0x016D (365)
	(uintptr_t)FUNC(&xbox::HalWriteSMCScratchRegister),              // 0x016E (366)
	(uintptr_t)FUNC(&xbox::UnknownAPI367),                           // 0x016F (367)
	(uintptr_t)FUNC(&xbox::UnknownAPI368),                           // 0x0170 (368)
	(uintptr_t)FUNC(&xbox::UnknownAPI369),                           // 0x0171 (369)
	(uintptr_t)FUNC(&xbox::XProfpControl),                           // 0x0172 (370) PROFILING
	(uintptr_t)FUNC(&xbox::XProfpGetData),                           // 0x0173 (371) PROFILING
	(uintptr_t)FUNC(&xbox::IrtClientInitFast),                       // 0x0174 (372) PROFILING
	(uintptr_t)FUNC(&xbox::IrtSweep),                                // 0x0175 (373) PROFILING
	(uintptr_t)FUNC(&xbox::MmDbgAllocateMemory),                     // 0x0176 (374) DEVKIT ONLY!
	(uintptr_t)FUNC(&xbox::MmDbgFreeMemory),                         // 0x0177 (375) DEVKIT ONLY!
	(uintptr_t)FUNC(&xbox::MmDbgQueryAvailablePages),                // 0x0178 (376) DEVKIT ONLY!
	(uintptr_t)FUNC(&xbox::MmDbgReleaseAddress),                     // 0x0179 (377) DEVKIT ONLY!
	(uintptr_t)FUNC(&xbox::MmDbgWriteCheck),                         // 0x017A (378) DEVKIT ONLY!
};
