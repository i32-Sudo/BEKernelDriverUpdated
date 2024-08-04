#pragma once

#include "../kernel/struct.h"
#include "../kernel/log.h"
#include "../kernel/kernelTools.h"
#include "../kernel/xor.h"

#define BB_POOL_TAG 'Esk' // For Recognition

NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound, int index = 0) {
    ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
    if (!ppFound || !pattern || !base)
        return STATUS_ACCESS_DENIED;

    int cIndex = 0;
    for (ULONG_PTR i = 0; i < size - len; i++) {
        BOOLEAN found = TRUE;
        for (ULONG_PTR j = 0; j < len; j++) {
            if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j]) {
                found = FALSE;
                break;
            }
        }
        if (found && cIndex++ == index) {
            *ppFound = (PUCHAR)base + i;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;

PVOID GetKernelBase(OUT PULONG pSize) {
    if (g_KernelBase) {
        if (pSize)
            *pSize = g_KernelSize;
        return g_KernelBase;
    }

    UNICODE_STRING routineName;
    RtlUnicodeStringInit(&routineName, L"NtOpenFile");

    PVOID checkPtr = MmGetSystemRoutineAddress(&routineName);
    if (!checkPtr)
        return NULL;

    ULONG bytes = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (!bytes) {
        log("Invalid SystemModuleInformation size");
        return NULL;
    }

    PRTL_PROCESS_MODULES pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, BB_POOL_TAG);
    if (!pMods) {
        log("pMods = NULL");
        return NULL;
    }
    RtlZeroMemory(pMods, bytes);

    status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);
    if (NT_SUCCESS(status)) {
        PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;
        for (ULONG i = 0; i < pMods->NumberOfModules; i++) {
            if (checkPtr >= pMod[i].ImageBase && checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize)) {
                g_KernelBase = pMod[i].ImageBase;
                g_KernelSize = pMod[i].ImageSize;
                if (pSize)
                    *pSize = g_KernelSize;
                break;
            }
        }
    }
    ExFreePoolWithTag(pMods, BB_POOL_TAG);
    return g_KernelBase;
}

NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound, PVOID base = nullptr) {
    if (!ppFound)
        return STATUS_ACCESS_DENIED;

    if (!base)
        base = GetKernelBase(&g_KernelSize);
    if (!base)
        return STATUS_ACCESS_DENIED;

    PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
    if (!pHdr)
        return STATUS_ACCESS_DENIED;

    PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));
    for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++) {
        ANSI_STRING s1, s2;
        RtlInitAnsiString(&s1, section);
        RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
        if (RtlCompareString(&s1, &s2, TRUE) == 0) {
            PVOID ptr = NULL;
            NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
            if (NT_SUCCESS(status)) {
                *(PULONG64)ppFound = (ULONG_PTR)ptr;
                return status;
            }
        }
    }
    return STATUS_ACCESS_DENIED;
}

extern "C" bool LocatePiDDB(PERESOURCE * lock, PRTL_AVL_TABLE * table) {
    PVOID PiDDBLockPtr = nullptr, PiDDBCacheTablePtr = nullptr;

    if (NT_SUCCESS(BBScanSection("PAGE", PiDDBLockPtr_sig_win10, 0, sizeof(PiDDBLockPtr_sig_win10) - 1, reinterpret_cast<PVOID*>(&PiDDBLockPtr)))) {
        PiDDBLockPtr = PVOID((uintptr_t)PiDDBLockPtr + 28);
        log("Win10 Signature Found");
    } else {
        if (NT_SUCCESS(BBScanSection("PAGE", PiDDBLockPtr_sig_win11, 0, sizeof(PiDDBLockPtr_sig_win11) - 1, reinterpret_cast<PVOID*>(&PiDDBLockPtr)))) {
            PiDDBLockPtr = PVOID((uintptr_t)PiDDBLockPtr + 16);
            log("Win11 Signature Found");
        } else {
            log("Could not find PiDDB for Win10 or Win11...");
            return false;
        }
    }

    if (!NT_SUCCESS(BBScanSection("PAGE", PiDDBCacheTablePtr_sig, 0, sizeof(PiDDBCacheTablePtr_sig) - 1, reinterpret_cast<PVOID*>(&PiDDBCacheTablePtr)))) {
        log("Unable to find PiDDBCacheTablePtr sig");
        return false;
    }

    PiDDBCacheTablePtr = PVOID((uintptr_t)PiDDBCacheTablePtr + 3);

    *lock = (PERESOURCE)(ResolveRelativeAddress(PiDDBLockPtr, 3, 7));
    *table = (PRTL_AVL_TABLE)(ResolveRelativeAddress(PiDDBCacheTablePtr, 3, 7));

    return true;
}

PMM_UNLOADED_DRIVER MmUnloadedDrivers;
PULONG MmLastUnloadedDriver;

BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask) {
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return false;
    return (*szMask) == 0;
}

UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, char* szMask) {
    for (UINT64 i = 0; i < dwLen; i++)
        if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
            return (UINT64)(dwAddress + i);
    return 0;
}

BOOLEAN IsUnloadedDriverEntryEmpty(_In_ PMM_UNLOADED_DRIVER Entry) {
    return Entry->Name.MaximumLength == 0 || Entry->Name.Length == 0 || Entry->Name.Buffer == NULL;
}

BOOLEAN IsMmUnloadedDriversFilled(VOID) {
    for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index) {
        PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
        if (IsUnloadedDriverEntryEmpty(Entry))
            return false;
    }
    return true;
}

ERESOURCE PsLoadedModuleResource;

namespace clear {

    BOOL clearCache(UNICODE_STRING DriverName, ULONG timeDateStamp) {
        PERESOURCE PiDDBLock;
        PRTL_AVL_TABLE PiDDBCacheTable;
        if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable)) {
            log("ClearCache Failed");
            return false;
        }

        PiDDBCacheEntry lookupEntry = { };
        lookupEntry.DriverName = DriverName;
        lookupEntry.TimeDateStamp = timeDateStamp;

        ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);
        auto pFoundEntry = (PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry);
        if (!pFoundEntry) {
            ExReleaseResourceLite(PiDDBLock);
            log("ClearCache Failed (Not found)");
            return false;
        }

        RemoveEntryList(&pFoundEntry->List);
        if (!RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry)) {
            log("RtlDeleteElementFromTableAVL Failed!");
            return false;
        }

        ExReleaseResourceLite(PiDDBLock);
        log("Cache cleared");
        return true;
    }

    BOOL clearHashBucket(UNICODE_STRING DriverName) {
        char* CIDLLString = "ci.dll";
        CONST PVOID CIDLLBase = GetKernelModuleBase(CIDLLString);

        if (!CIDLLBase) {
            log("Couldn't Find CIDDLBase");
            return false;
        }

        char* pKernelBucketHashPattern_21H1 = KernelBucketHashPattern_21H1;
        char* pKernelBucketHashMask_21H1 = KernelBucketHashMask_21H1;

        char* pKernelBucketHashPattern_22H2 = KernelBucketHashPattern_22H2;
        char* pKernelBucketHashMask_22H2 = KernelBucketHashMask_22H2;

        PVOID SignatureAddress = FindPatternImage((PCHAR)CIDLLBase, pKernelBucketHashPattern_21H1, pKernelBucketHashMask_21H1);
        if (!SignatureAddress) {
            SignatureAddress = FindPatternImage((PCHAR)CIDLLBase, pKernelBucketHashPattern_22H2, pKernelBucketHashMask_22H2);
            if (!SignatureAddress) {
                log("Couldn't find signature address for KernelBucketHash");
                return false;
            }
        }

        CONST ULONGLONG* g_KernelHashBucketList = (ULONGLONG*)ResolveRelativeAddress(SignatureAddress, 3, 7);
        if (!g_KernelHashBucketList) {
            return false;
        }

        LARGE_INTEGER Time{};
        KeQuerySystemTimePrecise(&Time);

        BOOL Status = FALSE;
        for (ULONGLONG i = *g_KernelHashBucketList; i; i = *(ULONGLONG*)i) {
            CONST PWCHAR wsName = PWCH(i + 0x48);
            if (wcsstr(wsName, DriverName.Buffer)) {
                PUCHAR Hash = PUCHAR(i + 0x18);
                for (UINT j = 0; j < 20; j++)
                    Hash[j] = UCHAR(RtlRandomEx(&Time.LowPart) % 255);
                Status = TRUE;
            }
        }

        if (!Status) {
            log("KernelHashBucket Failed to Clean");
            return false;
        } else {
            log("KernelHashBucket Cleaned!");
            return true;
        }
    }

    BOOL CleanMmu(UNICODE_STRING DriverName) {
        auto ps_loaded = GetPsLoaded();

        if (!ps_loaded) {
            log("Failed to get ps_loaded resource");
            return false;
        }

        ExAcquireResourceExclusiveLite(ps_loaded, TRUE);

        BOOLEAN Modified = FALSE;
        BOOLEAN Filled = IsMmuFilled();

        for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index) {
            PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
            if (IsUnloadEmpty(Entry)) {
                continue;
            }
            if (Modified) {
                PMM_UNLOADED_DRIVER PrevEntry = &GetMmuAddress()[Index - 1];
                RtlCopyMemory(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));
                if (Index == MM_UNLOADED_DRIVERS_SIZE - 1) {
                    RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
                }
            } else if (RtlEqualUnicodeString(&DriverName, &Entry->Name, TRUE)) {
                PVOID BufferPool = Entry->Name.Buffer;
                RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
                ExFreePoolWithTag(BufferPool, 'TDmM');
                *GetMmlAddress() = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *GetMmlAddress()) - 1;
                Modified = TRUE;
            }
        }

        if (Modified) {
            ULONG64 PreviousTime = 0;
            for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index) {
                PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
                if (IsUnloadEmpty(Entry)) {
                    continue;
                }
                if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime) {
                    Entry->UnloadTime = PreviousTime - RandomNumber();
                }
                PreviousTime = Entry->UnloadTime;
            }
            CleanMmu(DriverName);
        }

        ExReleaseResourceLite(ps_loaded);

        if (!Modified) {
            log("No modifications were made");
            return false;
        } else {
            log("Modifications to MMU/MML Were made and have been cleared...");
            return true;
        }
    }
}
