#pragma once

#ifdef _MSC_VER
#define _KLI_FORCEINLINE __forceinline
#else
#define _KLI_FORCEINLINE __attribute__((always_inline))
#endif

#ifndef KLI_DONT_INLINE
#define KLI_FORCEINLINE _KLI_FORCEINLINE
#else
#define KLI_FORCEINLINE inline
#endif

#define driver_api inline

namespace driver
{
	enum status : int32_t
	{
		failed_signature_scan = 0,
		failed_intialization = 0,
		failed_sanity_check = 0,
		successful_operation = STATUS_SUCCESS,
		failed_entry = STATUS_FAILED_DRIVER_ENTRY,
		failed_get_module_base = 0,
	};
}

namespace kli
{
	namespace cache {
		inline uintptr_t kernel_base;
	}

	namespace literals {
		KLI_FORCEINLINE constexpr size_t operator ""_KiB( size_t num ) { return num << 10; }
		KLI_FORCEINLINE constexpr size_t operator ""_MiB( size_t num ) { return num << 20; }
		KLI_FORCEINLINE constexpr size_t operator ""_GiB( size_t num ) { return num << 30; }
		KLI_FORCEINLINE constexpr size_t operator ""_TiB( size_t num ) { return num << 40; }
	}
	using namespace literals;

	namespace hash {
		namespace detail {
			template <typename Size>
			struct fnv_constants;

			template <>
			struct fnv_constants<UINT32>
			{
				constexpr static UINT32 default_offset_basis = 0x811C9DC5UL;
				constexpr static UINT32 prime = 0x01000193UL;
			};

			template <>
			struct fnv_constants<UINT64>
			{
				constexpr static UINT64 default_offset_basis = 0xCBF29CE484222325ULL;
				constexpr static UINT64 prime = 0x100000001B3ULL;
			};

			template <typename Char>
			struct char_traits;

			template <>
			struct char_traits<char>
			{
				KLI_FORCEINLINE static constexpr char to_lower( char c ) { return c | ' '; };
				KLI_FORCEINLINE static constexpr char to_upper( char c ) { return c & '_'; }; // equivalent to c & ~' '
				KLI_FORCEINLINE static constexpr char flip_case( char c ) { return c ^ ' '; };
				KLI_FORCEINLINE static constexpr bool is_caps( char c ) { return (c & ' ') == ' '; }
			};

			template <>
			struct char_traits<wchar_t>
			{
				KLI_FORCEINLINE static constexpr wchar_t to_lower( wchar_t c ) { return c | L' '; };
				KLI_FORCEINLINE static constexpr wchar_t to_upper( wchar_t c ) { return c & L'_'; }; // equivalent to c & ~' '
				KLI_FORCEINLINE static constexpr wchar_t flip_case( wchar_t c ) { return c ^ L' '; };
				KLI_FORCEINLINE static constexpr bool is_caps( wchar_t c ) { return (c & L' ') == L' '; }
			};
		}

		// Shortcuts for character traits
		template <typename Char> KLI_FORCEINLINE constexpr Char to_lower( Char c ) { return detail::char_traits<Char>::to_lower( c ); }
		template <typename Char> KLI_FORCEINLINE constexpr Char to_upper( Char c ) { return detail::char_traits<Char>::to_upper( c ); }
		template <typename Char> KLI_FORCEINLINE constexpr Char flip_case( Char c ) { return detail::char_traits<Char>::flip_case( c ); }

		template <typename Type, typename Char, bool ToLower = false>
		KLI_FORCEINLINE constexpr Type hash_fnv1a( const Char* str )
		{
			Type val = detail::fnv_constants<Type>::default_offset_basis;

			for ( ; *str != static_cast< Char >(0); ++str ) {
				Char c = *str;

				if constexpr ( ToLower )
					c = to_lower<Char>( c );

				val ^= static_cast< Type >(c);
				val *= static_cast< Type >(detail::fnv_constants<Type>::prime);
			}

			return val;
		}

		//
		// Dumb hack to force a constexpr value to be evaluated in compiletime
		//

		template <typename Type, Type Value>
		struct force_cx
		{
			constexpr static auto value = Value;
		};

#define _KLI_HASH_RTS(str) (::kli::hash::hash_fnv1a<UINT64, std::remove_const_t<std::remove_reference_t<decltype(*(str))>>, false>((str)))
#define _KLI_HASH_RTS_TOLOWER(str) (::kli::hash::hash_fnv1a<UINT64, std::remove_const_t<std::remove_reference_t<decltype(*(str))>>, true>((str)))

#define _KLI_HASH_STR(str) (::kli::hash::force_cx<UINT64, ::kli::hash::hash_fnv1a<UINT64, std::remove_const_t<std::remove_reference_t<decltype(*(str))>>, false>((str))>::value)
#define _KLI_HASH_STR_TOLOWER(str) (::kli::hash::force_cx<UINT64, ::kli::hash::hash_fnv1a<UINT64, std::remove_const_t<std::remove_reference_t<decltype(*(str))>>, true>((str))>::value)

#ifndef KLI_USE_TOLOWER
		// Don't use tolower
#define KLI_HASH_RTS(str) _KLI_HASH_RTS(str)
#define KLI_HASH_STR(str) _KLI_HASH_STR(str)
#else
		// Use tolower
#define KLI_HASH_RTS(str) _KLI_HASH_RTS_TOLOWER(str)
#define KLI_HASH_STR(str) _KLI_HASH_STR_TOLOWER(str)
#endif
	}

	namespace detail {
#pragma pack(push, 1)
		enum exception_vector
		{
			VECTOR_DIVIDE_ERROR_EXCEPTION = 0,
			VECTOR_DEBUG_EXCEPTION = 1,
			VECTOR_NMI_INTERRUPT = 2,
			VECTOR_BREAKPOINT_EXCEPTION = 3,
			VECTOR_OVERFLOW_EXCEPTION = 4,
			VECTOR_BOUND_EXCEPTION = 5,
			VECTOR_UNDEFINED_OPCODE_EXCEPTION = 6,
			VECTOR_DEVICE_NOT_AVAILABLE_EXCEPTION = 7,
			VECTOR_DOUBLE_FAULT_EXCEPTION = 8,
			VECTOR_COPROCESSOR_SEGMENT_OVERRUN = 9,
			VECTOR_INVALID_TSS_EXCEPTION = 10,
			VECTOR_SEGMENT_NOT_PRESENT = 11,
			VECTOR_STACK_FAULT_EXCEPTION = 12,
			VECTOR_GENERAL_PROTECTION_EXCEPTION = 13,
			VECTOR_PAGE_FAULT_EXCEPTION = 14,
			VECTOR_X87_FLOATING_POINT_ERROR = 16,
			VECTOR_ALIGNMENT_CHECK_EXCEPTION = 17,
			VECTOR_MACHINE_CHECK_EXCEPTION = 18,
			VECTOR_SIMD_FLOATING_POINT_EXCEPTION = 19,
			VECTOR_VIRTUALIZATION_EXCEPTION = 20,
			VECTOR_SECURITY_EXCEPTION = 30
		};

		union idt_entry
		{
			struct
			{
				UINT64 low64;
				UINT64 high64;
			} split;

			struct
			{
				UINT16 offset_low;

				union
				{
					UINT16 flags;

					struct
					{
						UINT16 rpl : 2;
						UINT16 table : 1;
						UINT16 index : 13;
					};
				} segment_selector;
				UINT8 reserved0;
				union
				{
					UINT8 flags;

					struct
					{
						UINT8 gate_type : 4;
						UINT8 storage_segment : 1;
						UINT8 dpl : 2;
						UINT8 present : 1;
					};
				} type_attr;

				UINT16 offset_mid;
				UINT32 offset_high;
				UINT32 reserved1;
			};
		};

		struct idtr
		{
			UINT16 idt_limit;
			UINT64 idt_base;

			KLI_FORCEINLINE idt_entry* operator []( size_t index ) {
				return &(( idt_entry* ) idt_base) [ index ];
			}
		};
#pragma pack(pop)

		typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
			UINT16   e_magic;                     // Magic number
			UINT16   e_cblp;                      // Bytes on last page of file
			UINT16   e_cp;                        // Pages in file
			UINT16   e_crlc;                      // Relocations
			UINT16   e_cparhdr;                   // GetSize of header in paragraphs
			UINT16   e_minalloc;                  // Minimum extra paragraphs needed
			UINT16   e_maxalloc;                  // Maximum extra paragraphs needed
			UINT16   e_ss;                        // Initial (relative) SS value
			UINT16   e_sp;                        // Initial SP value
			UINT16   e_csum;                      // Checksum
			UINT16   e_ip;                        // Initial IP value
			UINT16   e_cs;                        // Initial (relative) CS value
			UINT16   e_lfarlc;                    // File address of relocation table
			UINT16   e_ovno;                      // Overlay number
			UINT16   e_res [ 4 ];                    // Reserved words
			UINT16   e_oemid;                     // OEM identifier (for e_oeminfo)
			UINT16   e_oeminfo;                   // OEM information; e_oemid specific
			UINT16   e_res2 [ 10 ];                  // Reserved words
			INT32    e_lfanew;                    // File address of new exe header
		} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

		typedef struct _IMAGE_FILE_HEADER {
			UINT16    Machine;
			UINT16    NumberOfSections;
			UINT32   TimeDateStamp;
			UINT32   PointerToSymbolTable;
			UINT32   NumberOfSymbols;
			UINT16    SizeOfOptionalHeader;
			UINT16    Characteristics;
		} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

		typedef struct _IMAGE_DATA_DIRECTORY {
			UINT32   VirtualAddress;
			UINT32   Size;
		} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

		typedef struct _IMAGE_OPTIONAL_HEADER64 {
			UINT16        Magic;
			UINT8        MajorLinkerVersion;
			UINT8        MinorLinkerVersion;
			UINT32       SizeOfCode;
			UINT32       SizeOfInitializedData;
			UINT32       SizeOfUninitializedData;
			UINT32       AddressOfEntryPoint;
			UINT32       BaseOfCode;
			UINT64   ImageBase;
			UINT32       SectionAlignment;
			UINT32       FileAlignment;
			UINT16        MajorOperatingSystemVersion;
			UINT16        MinorOperatingSystemVersion;
			UINT16        MajorImageVersion;
			UINT16        MinorImageVersion;
			UINT16        MajorSubsystemVersion;
			UINT16        MinorSubsystemVersion;
			UINT32       Win32VersionValue;
			UINT32       SizeOfImage;
			UINT32       SizeOfHeaders;
			UINT32       CheckSum;
			UINT16        Subsystem;
			UINT16        DllCharacteristics;
			UINT64   SizeOfStackReserve;
			UINT64   SizeOfStackCommit;
			UINT64   SizeOfHeapReserve;
			UINT64   SizeOfHeapCommit;
			UINT32       LoaderFlags;
			UINT32       NumberOfRvaAndSizes;
			IMAGE_DATA_DIRECTORY DataDirectory [ 16 ];
		} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

		typedef struct _IMAGE_NT_HEADERS64 {
			UINT32 Signature;
			IMAGE_FILE_HEADER FileHeader;
			IMAGE_OPTIONAL_HEADER64 OptionalHeader;
		} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

		typedef struct _IMAGE_EXPORT_DIRECTORY {
			UINT32   Characteristics;
			UINT32   TimeDateStamp;
			UINT16   MajorVersion;
			UINT16   MinorVersion;
			UINT32   Name;
			UINT32   Base;
			UINT32   NumberOfFunctions;
			UINT32   NumberOfNames;
			UINT32   AddressOfFunctions;     // RVA from base of image
			UINT32   AddressOfNames;         // RVA from base of image
			UINT32   AddressOfNameOrdinals;  // RVA from base of image
		} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

	}

	template <UINT64 ExportHash>
	KLI_FORCEINLINE uintptr_t find_kernel_export( )
	{
		if ( !cache::kernel_base )
			cache::kernel_base = ( uintptr_t ) globals::ntos_image_base;

		const auto dos_header = ( detail::PIMAGE_DOS_HEADER ) cache::kernel_base;
		const auto nt_headers = ( detail::PIMAGE_NT_HEADERS64 ) (cache::kernel_base + dos_header->e_lfanew);
		const auto export_directory = ( detail::PIMAGE_EXPORT_DIRECTORY ) (cache::kernel_base +
			nt_headers->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress);

		const auto address_of_functions = ( UINT32* ) (cache::kernel_base + export_directory->AddressOfFunctions);
		const auto address_of_names = ( UINT32* ) (cache::kernel_base + export_directory->AddressOfNames);
		const auto address_of_name_ordinals = ( UINT16* ) (cache::kernel_base + export_directory->AddressOfNameOrdinals);

		for ( UINT32 i = 0; i < export_directory->NumberOfNames; ++i )
		{
			const auto export_entry_name = ( char* ) (cache::kernel_base + address_of_names [ i ]);
			const auto export_entry_hash = KLI_HASH_RTS( export_entry_name );

			// kys
			if ( export_entry_hash == ExportHash )
			{
				return cache::kernel_base + address_of_functions [ address_of_name_ordinals [ i ] ];
			}
		}

		__debugbreak( );
		return { };
	}

	template <UINT64 ExportHash>
	KLI_FORCEINLINE uintptr_t find_kernel_export_cached( )
	{
		static uintptr_t address = 0;
		if ( !address )
			address = find_kernel_export<ExportHash>( );

		return address;
	}
}

#define qtx_import(name) ((decltype(&##name))(::kli::find_kernel_export_cached<KLI_HASH_STR(#name)>()))