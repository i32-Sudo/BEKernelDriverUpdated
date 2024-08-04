#include "intrin.h"

namespace crt
{
    INT klower( int c )
    {
        if ( c >= 'A' && c <= 'Z' )
            return c + 'a' - 'A';
        else
            return c;
    }

    INT kwcscmp( const wchar_t* s1, const wchar_t* s2 )
    {
        while ( *s1 == *s2++ )
            if ( *s1++ == '\0' )
                return (0);
        /* XXX assumes wchar_t = int */
        return (*( const unsigned int* ) s1 - *(const unsigned int*)--s2);
    }

    CHAR* kLowerStr( CHAR* Str )
    {
        for ( CHAR* S = Str; *S; ++S )
        {
            *S = ( CHAR ) klower( *S );
        }
        return Str;
    }

    SIZE_T kstrlen( const char* str )
    {
        const char* s;
        for ( s = str; *s; ++s );
        return (s - str);
    }

    INT kstrncmp( const char* s1, const char* s2, size_t n )
    {
        if ( n == 0 )
            return (0);
        do {
            if ( *s1 != *s2++ )
                return (*( unsigned char* ) s1 - *(unsigned char*)--s2);
            if ( *s1++ == 0 )
                break;
        } while ( --n != 0 );
        return (0);
    }

    INT kstrcmp( const char* s1, const char* s2 )
    {
        while ( *s1 == *s2++ )
            if ( *s1++ == 0 )
                return (0);
        return (*( unsigned char* ) s1 - *(unsigned char*)--s2);
    }

    CHAR* kstrstr( const char* s, const char* find )
    {
        char c, sc;
        size_t len;
        if ( (c = *find++) != 0 )
        {
            len = kstrlen( find );
            do
            {
                do
                {
                    if ( (sc = *s++) == 0 )
                    {
                        return (NULL);
                    }
                } while ( sc != c );
            } while ( kstrncmp( s, find, len ) != 0 );
            s--;
        }
        return (( char* ) s);
    }

    INT kmemcmp( const void* s1, const void* s2, size_t n )
    {
        const unsigned char* p1 = ( const unsigned char* ) s1;
        const unsigned char* end1 = p1 + n;
        const unsigned char* p2 = ( const unsigned char* ) s2;
        int                   d = 0;
        for ( ;;) {
            if ( d || p1 >= end1 ) break;
            d = ( int ) *p1++ - ( int ) *p2++;
            if ( d || p1 >= end1 ) break;
            d = ( int ) *p1++ - ( int ) *p2++;
            if ( d || p1 >= end1 ) break;
            d = ( int ) *p1++ - ( int ) *p2++;
            if ( d || p1 >= end1 ) break;
            d = ( int ) *p1++ - ( int ) *p2++;
        }
        return d;
    }

    INT kMemcmp( const void* str1, const void* str2, size_t count )
    {
        register const unsigned char* s1 = ( const unsigned char* ) str1;
        register const unsigned char* s2 = ( const unsigned char* ) str2;
        while ( count-- > 0 )
        {
            if ( *s1++ != *s2++ )
                return s1 [ -1 ] < s2 [ -1 ] ? -1 : 1;
        }
        return 0;
    }


    VOID* kmemcpy( void* dest, const void* src, size_t len )
    {
        char* d = ( char* ) dest;
        const char* s = ( const char* ) src;
        while ( len-- )
            *d++ = *s++;
        return dest;
    }

    VOID* kmemset( void* dest, UINT8 c, size_t count )
    {
        size_t blockIdx;
        size_t blocks = count >> 3;
        size_t bytesLeft = count - (blocks << 3);
        UINT64 cUll =
            c
            | ((( UINT64 ) c) << 8)
            | ((( UINT64 ) c) << 16)
            | ((( UINT64 ) c) << 24)
            | ((( UINT64 ) c) << 32)
            | ((( UINT64 ) c) << 40)
            | ((( UINT64 ) c) << 48)
            | ((( UINT64 ) c) << 56);

        UINT64* destPtr8 = ( UINT64* ) dest;
        for ( blockIdx = 0; blockIdx < blocks; blockIdx++ ) destPtr8 [ blockIdx ] = cUll;

        if ( !bytesLeft ) return dest;

        blocks = bytesLeft >> 2;
        bytesLeft = bytesLeft - (blocks << 2);

        UINT32* destPtr4 = ( UINT32* ) &destPtr8 [ blockIdx ];
        for ( blockIdx = 0; blockIdx < blocks; blockIdx++ ) destPtr4 [ blockIdx ] = ( UINT32 ) cUll;

        if ( !bytesLeft ) return dest;

        blocks = bytesLeft >> 1;
        bytesLeft = bytesLeft - (blocks << 1);

        UINT16* destPtr2 = ( UINT16* ) &destPtr4 [ blockIdx ];
        for ( blockIdx = 0; blockIdx < blocks; blockIdx++ ) destPtr2 [ blockIdx ] = ( UINT16 ) cUll;

        if ( !bytesLeft ) return dest;

        UINT8* destPtr1 = ( UINT8* ) &destPtr2 [ blockIdx ];
        for ( blockIdx = 0; blockIdx < bytesLeft; blockIdx++ ) destPtr1 [ blockIdx ] = ( UINT8 ) cUll;

        return dest;
    }
}

namespace modules
{
    auto get_kernel_export( uintptr_t Base, LPCSTR routine_name ) -> UINT64
    {
        if ( !Base ) return NULL;

        PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER ) (Base);
        if ( dosHeader->e_magic != IMAGE_DOS_SIGNATURE )
            return 0;

        PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast< PIMAGE_NT_HEADERS64 >(( UINT64 ) ( Base ) +dosHeader->e_lfanew);

        UINT32 exportsRva = ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
        if ( !exportsRva )
            return 0;

        PIMAGE_EXPORT_DIRECTORY exports = reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >(( UINT64 ) ( Base ) +exportsRva);
        UINT32* nameRva = reinterpret_cast< UINT32* >(( UINT64 ) ( Base ) +exports->AddressOfNames);

        for ( UINT32 i = 0; i < exports->NumberOfNames; ++i )
        {
            CHAR* func = reinterpret_cast< CHAR* >(( UINT64 ) ( Base ) +nameRva [ i ]);
            if ( crt::kstrcmp( func, routine_name ) == 0 )
            {
                UINT32* funcRva = ( UINT32* ) (( UINT64 ) ( Base ) +exports->AddressOfFunctions);
                UINT16* ordinalRva = ( UINT16* ) (( UINT64 ) ( Base ) +exports->AddressOfNameOrdinals);

                return ( UINT64 ) ( Base ) +funcRva [ ordinalRva [ i ] ];
            }
        }
        return 0;
    }
    
    auto get_random( ) -> uint32_t
    {
        auto seed = qtx_import( KeQueryTimeIncrement )();
        return qtx_import( RtlRandomEx )( &seed );
    }

    _declspec(noinline) auto resolve_address( 
        uintptr_t Instruction, 
        ULONG OffsetOffset, 
        ULONG InstructionSize ) -> uintptr_t
    {
        LONG RipOffset = *( PLONG ) (Instruction + OffsetOffset);
        auto ResolvedAddr = (
                Instruction + 
                InstructionSize + 
                RipOffset);

        return ResolvedAddr;
    }
    
    _declspec(noinline) auto get_ntos_base_address( ) -> uintptr_t
    {
        typedef unsigned char uint8_t;
        auto Idt_base = reinterpret_cast< uintptr_t >(KeGetPcr( )->IdtBase);
        auto align_page = *reinterpret_cast< uintptr_t* >(Idt_base + 4) >> 0xc << 0xc;

        for ( ; align_page; align_page -= PAGE_SIZE )
        {
            for ( int index = 0; index < PAGE_SIZE - 0x7; index++ )
            {
                auto current_address = static_cast< intptr_t >(align_page) + index;

                if ( *reinterpret_cast< uint8_t* >(current_address) == 0x48
                    && *reinterpret_cast< uint8_t* >(current_address + 1) == 0x8D
                    && *reinterpret_cast< uint8_t* >(current_address + 2) == 0x1D
                    && *reinterpret_cast< uint8_t* >(current_address + 6) == 0xFF ) //48 8d 1D ?? ?? ?? FF
                {
                    // rva our virtual address lol
                    auto Ntosbase = resolve_address( current_address, 3, 7 );
                    if ( !(( UINT64 ) Ntosbase & 0xfff) )
                    {
                        return Ntosbase;
                    }
                }
            }
        }
        return 0;
    }

    _declspec(noinline) void* get_system_information(SYSTEM_INFORMATION_CLASS information_class)
    {
        unsigned long size = 32;
        char buffer[32];

        qtx_import(ZwQuerySystemInformation)(information_class, buffer, size, &size);

        void* info = qtx_import(ExAllocatePool)(NonPagedPool, size);

        if (!info)
            return nullptr;

        if (!NT_SUCCESS( qtx_import( ZwQuerySystemInformation )(information_class, info, size, &size)))
        {
            qtx_import(ExFreePoolWithTag)(info, 0);
            return nullptr;
        }

        return info;
    }

    _declspec(noinline) auto find_section( uintptr_t ModuleBase, char* SectionName ) -> uintptr_t
    {
        PIMAGE_NT_HEADERS NtHeaders = ( PIMAGE_NT_HEADERS ) (ModuleBase + (( PIMAGE_DOS_HEADER ) ModuleBase)->e_lfanew);
        PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION( NtHeaders );

        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            PIMAGE_SECTION_HEADER Section = &Sections [ i ];
            if ( crt::kmemcmp( Section->Name, SectionName, 5 ) == 0 )
            {
                return ModuleBase + Section->VirtualAddress;
            }
        }

        return 0;
    }

    _declspec(noinline) uintptr_t get_kernel_module(const char* name)
    {
        const auto to_lower = [](char* string) -> const char*
        {
            for (char* pointer = string; *pointer != '\0'; ++pointer)
            {
                *pointer = (char)(short)tolower(*pointer);
            }

            return string;
        };

        const PRTL_PROCESS_MODULES info = (PRTL_PROCESS_MODULES)get_system_information(SystemModuleInformation);

        if (!info)
            return NULL;

        for (size_t i = 0; i < info->NumberOfModules; ++i)
        {
            const auto& mod = info->Modules[i];

            if (crt::strcmp(to_lower_c((char*)mod.FullPathName + mod.OffsetToFileName), name) == 0)
            {
                const void* address = mod.ImageBase;
                qtx_import(ExFreePoolWithTag)(info, 0);
                return (uintptr_t)address;
            }
        }

        qtx_import( ExFreePoolWithTag )(info, 0);
        return NULL;
    }

    _declspec(noinline) bool safe_copy( void* dst, void* src, size_t size )
    {
        SIZE_T bytes = 0;

        if (qtx_import(MmCopyVirtualMemory)(
            qtx_import(IoGetCurrentProcess)( ),
            src,
            qtx_import( IoGetCurrentProcess )(),
            dst, 
            size, 
            KernelMode,
            &bytes ) == STATUS_SUCCESS && bytes == size)
        {
            return true;
        }

        return false;
    }


    _declspec(noinline) TABLE_SEARCH_RESULT mi_find_node_or_parent( IN PMM_AVL_TABLE table, ULONG_PTR starting_vpn, PMMADDRESS_NODE* node_or_parent )
    {
        PMMADDRESS_NODE child;
        PMMADDRESS_NODE node_to_examine;
        PMMVAD_SHORT    vpn_compare;
        ULONG_PTR       start_vpn;
        ULONG_PTR       end_vpn;

        if (table->NumberGenericTableElements == 0)
            return TableEmptyTree;

        node_to_examine = (PMMADDRESS_NODE)(table->BalancedRoot);

        for (;;)
        {
            vpn_compare = (PMMVAD_SHORT)node_to_examine;
            start_vpn = vpn_compare->StartingVpn;
            end_vpn = vpn_compare->EndingVpn;

            if (starting_vpn < start_vpn)
            {
                child = node_to_examine->LeftChild;
                if (child != NULL)
                {
                    node_to_examine = child;
                }
                else
                {
                    *node_or_parent = node_to_examine;
                    return TableInsertAsLeft;
                }
            }
            else if (starting_vpn <= end_vpn)
            {
                *node_or_parent = node_to_examine;
                return TableFoundNode;
            }
            else
            {
                child = node_to_examine->RightChild;
                if (child != NULL)
                {
                    node_to_examine = child;
                }
                else
                {
                    *node_or_parent = node_to_examine;
                    return TableInsertAsRight;
                }
            }
        };
    }

    _declspec(noinline) uintptr_t attach_process( uintptr_t process )
    {
        auto current_thread = (uintptr_t)qtx_import(KeGetCurrentThread)( );
        if (!current_thread)
            return 0;

        auto apc_state = *(uintptr_t*)(current_thread + 0x98);
        auto old_process = *(uintptr_t*)(apc_state + 0x20);
        *(uintptr_t*)(apc_state + 0x20) = process;

        auto dir_table_base = *(uintptr_t*)(process + 0x28);

        __writecr3(dir_table_base);

        return old_process;
    }

    auto get_pattern( uintptr_t base, size_t range, const char* pattern, const char* mask ) -> uintptr_t
    {
        const auto check_mask = [ ] ( const char* base, const char* pattern, const char* mask ) -> bool
        {
            for ( ; *mask; ++base, ++pattern, ++mask )
            {
                if ( *mask == 'x' && *base != *pattern )
                {
                    return false;
                }
            }

            return true;
        };

        range = range - crt::kstrlen( mask );

        for ( size_t i = 0; i < range; ++i )
        {
            if ( check_mask( ( const char* ) base + i, pattern, mask ) )
            {
                return base + i;
            }
        }

        return NULL;
    }

    auto find_pattern( uintptr_t Base, CHAR* Pattern, CHAR* Mask ) -> uintptr_t
    {
        IMAGE_NT_HEADERS* Headers { ( PIMAGE_NT_HEADERS ) (Base + (( PIMAGE_DOS_HEADER ) Base)->e_lfanew) };
        IMAGE_SECTION_HEADER* Sections { IMAGE_FIRST_SECTION( Headers ) };

        for ( auto i = 0; i < Headers->FileHeader.NumberOfSections; ++i )
        {
            IMAGE_SECTION_HEADER* Section { &Sections [ i ] };

            if ( !crt::kmemcmp( Section->Name, _( ".text" ), 5 ) || !crt::kmemcmp( Section->Name, _( "PAGE" ), 4 ) )
            {
                const auto match = get_pattern( Base + Section->VirtualAddress, Section->Misc.VirtualSize, Pattern, Mask );

                if ( match ) {
                    return (match);
                }
            }
        }

        return 0;
    }

    auto write_address( uintptr_t address, void* buffer, SIZE_T size, bool restore ) -> bool
    {
        NTSTATUS Status = { STATUS_SUCCESS };

        auto Mdl = qtx_import( IoAllocateMdl )(reinterpret_cast< void* >(address), size, false, false, false);

        qtx_import( MmProbeAndLockPages )(Mdl, KernelMode, IoReadAccess);

        auto Mapping = qtx_import( MmMapLockedPagesSpecifyCache )(Mdl, KernelMode, MmNonCached, nullptr, false, NormalPagePriority);

        Status = qtx_import( MmProtectMdlSystemAddress )(Mdl, PAGE_READWRITE);

        if ( Status != STATUS_SUCCESS )
        {
            print( " [log] -> failed to change page protection.\n" );
            qtx_import( MmUnmapLockedPages )(Mapping, Mdl);
            qtx_import( MmUnlockPages )(Mdl);
            qtx_import( IoFreeMdl )(Mdl);
        }

        crt::kmemcpy( Mapping, buffer, size );

        if ( restore )
        {
            Status = qtx_import( MmProtectMdlSystemAddress )(Mdl, PAGE_READONLY);

            if ( Status != STATUS_SUCCESS )
            {
                print( " [log] -> failed to restore page.\n" );

                qtx_import( MmUnmapLockedPages )(Mapping, Mdl);
                qtx_import( MmUnlockPages )(Mdl);
                qtx_import( IoFreeMdl )(Mdl);
            }
        }

        qtx_import( MmUnmapLockedPages )(Mapping, Mdl);
        qtx_import( MmUnlockPages )(Mdl);
        qtx_import( IoFreeMdl )(Mdl);

        return Status;
    }
}
