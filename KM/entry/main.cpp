#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include "IoCreateDriver/CreateDriver.h"
#include "../clean/clean.hpp"
#include "../kernel/log.h"
#include "../kernel/xor.h"
#include "../kernel/structures.hpp"
#include "../impl/imports.h"
#include "../impl/communication/interface.h"
#include "../impl/scanner.h"
#include "../impl/modules.h"
#include "../requests/get_module_base.cpp"
#include "../requests/read_physical_memory.cpp"
#include "../requests/write_physical_memory.cpp"
#include "../requests/signature_scanner.cpp"
#include "../requests/virtual_allocate.cpp"
#include "../impl/invoked.h"
#include "hook/hook.hpp"
 
/*
Setup:

- in (main.cpp) add hook driver & add hook settings
- in (impl/communication/interface.h) change driver handle identifier after the last \\
- in (processhyde/Hide.cpp) change executable name to hide to the usermode application
- Use VMProtect or another code mutator to make sure driver doesnt get signature scanned (as its public and BE/EAC will reverse it)

- get patchguard bypass.

- use my PdFwKrnl Mapper [github.com/i32-Sudo] or another mapper (DO NOT MANUAL MAP OR USE KDMAPPER, THIS IS DTC)
*/

extern "C" DRIVER_INITIALIZE DriverEntry;
EXTERN_C PLIST_ENTRY PsLoadedModuleList;

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    PVOID NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;
    PVOID LoadedImports;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef struct _KNMI_HANDLER_CALLBACK {
    struct _KNMI_HANDLER_CALLBACK* Next;
    void(*Callback)();
    void* Context;
    void* Handle;
} KNMI_HANDLER_CALLBACK, * PKNMI_HANDLER_CALLBACK;

typedef struct _KAFFINITY_EX {
    USHORT Count;
    USHORT Size;
    ULONG Reserved;
    ULONGLONG Bitmap[20];
} KAFFINITY_EX, * PKAFFINITY_EX;

typedef ULONG KEPROCESSORINDEX;
extern "C" NTSYSAPI BOOLEAN NTAPI KeInterlockedSetProcessorAffinityEx(PKAFFINITY_EX pAffinity, KEPROCESSORINDEX idxProcessor);

PKNMI_HANDLER_CALLBACK SigscanKiNmiCallbackListHead() {
    uintptr_t ntos_base_address = modules::get_ntos_base_address();
    char NmiSignature[] = "\x81\x25\x00\x00\x00\x00\x00\x00\x00\x00\xB9\x00\x00\x00\x00";
    char NmiSignatureMask[] = "xx????????x????";
    uintptr_t nmi_in_progress = modules::find_pattern(ntos_base_address, NmiSignature, NmiSignatureMask);
    return reinterpret_cast<PKNMI_HANDLER_CALLBACK>(nmi_in_progress);
}

PKNMI_HANDLER_CALLBACK KiNmiCallbackListHead = nullptr;

extern "C" NTSTATUS PreventNMIExecution() {
    KiNmiCallbackListHead = SigscanKiNmiCallbackListHead();
    PKNMI_HANDLER_CALLBACK CurrentNMI = KiNmiCallbackListHead;
    while (CurrentNMI) {
        uint8_t* nmi_in_progress = reinterpret_cast<uint8_t*>(KiNmiCallbackListHead);
        while (*nmi_in_progress != 0x48) {
            ++nmi_in_progress;
        }
        nmi_in_progress += 3;
        auto irql = KfRaiseIrql(0);
        ULONG cores = KeQueryActiveProcessorCount(NULL);
        for (auto i = 0ul; i < cores; ++i) {
            KeInterlockedSetProcessorAffinityEx((PKAFFINITY_EX)nmi_in_progress, i);
            InterlockedBitTestAndSet64(reinterpret_cast<LONG64*>(nmi_in_progress), i);
        }
        KeLowerIrql(irql);
        CurrentNMI = CurrentNMI->Next;
    }
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS OEPDriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    NTSTATUS status = STATUS_SUCCESS;
    KeEnterGuardedRegion();
    NTSTATUS NmiStatus = PreventNMIExecution();
    if (NmiStatus != STATUS_SUCCESS) {
        log(_("NMI Blocker Failed..."));
        return driver::status::failed_intialization;
    }
    if (initialize_hook() != driver::status::successful_operation)
        return driver::status::failed_intialization;
    if (initialize_ioctl() != driver::status::successful_operation)
        return driver::status::failed_intialization;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _(" - OEP Started"));

    PKLDR_DATA_TABLE_ENTRY pSelfEntry = nullptr;
    auto pNext = PsLoadedModuleList->Flink;
    if (pNext) {
        while (pNext != PsLoadedModuleList) {
            auto pEntry = CONTAINING_RECORD(pNext, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (DriverObject->DriverStart == pEntry->DllBase) {
                pSelfEntry = pEntry;
                break;
            }
            pNext = pNext->Flink;
        }
    }
    if (pSelfEntry) {
        KIRQL kIrql = KeRaiseIrqlToDpcLevel();
        auto pPrevEntry = (PKLDR_DATA_TABLE_ENTRY)pSelfEntry->InLoadOrderLinks.Blink;
        auto pNextEntry = (PKLDR_DATA_TABLE_ENTRY)pSelfEntry->InLoadOrderLinks.Flink;
        if (pPrevEntry) {
            pPrevEntry->InLoadOrderLinks.Flink = pSelfEntry->InLoadOrderLinks.Flink;
        }
        if (pNextEntry) {
            pNextEntry->InLoadOrderLinks.Blink = pSelfEntry->InLoadOrderLinks.Blink;
        }
        pSelfEntry->InLoadOrderLinks.Flink = (PLIST_ENTRY)pSelfEntry;
        pSelfEntry->InLoadOrderLinks.Blink = (PLIST_ENTRY)pSelfEntry;
        KeLowerIrql(kIrql);
    }

    CleanDriverSys(UNICODE_STRING(RTL_CONSTANT_STRING(L"DriverKL.sys")), 0x63EF9904);
    CleanDriverSys(UNICODE_STRING(RTL_CONSTANT_STRING(L"PdFwKrnl.sys")), 0x611AB60D);

    KeLeaveGuardedRegion();
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _(" - Driver Started"));
    return IoCreateDriver(OEPDriverEntry);
}
