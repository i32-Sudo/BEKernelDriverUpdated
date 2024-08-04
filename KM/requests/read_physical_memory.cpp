#pragma once
namespace request
{
    auto read_physical(
        uintptr_t address,
        PVOID buffer,
        size_t size,
        size_t* bytes ) -> NTSTATUS
    {
        MM_COPY_ADDRESS target_address = { 0 };
        target_address.PhysicalAddress.QuadPart = address;
        return qtx_import( MmCopyMemory )(buffer, target_address, size, MM_COPY_MEMORY_PHYSICAL, bytes);
    }

    auto read_virtual(
        uintptr_t address,
        PVOID buffer,
        size_t size,
        size_t* bytes ) -> NTSTATUS
    {
        MM_COPY_ADDRESS target_address = { 0 };
        target_address.PhysicalAddress.QuadPart = address;
        return qtx_import( MmCopyMemory )(buffer, target_address, size, MM_COPY_MEMORY_VIRTUAL, bytes);
    }

    template <class t> 
    t read_kernel_virtual( uintptr_t address ) {

        t response { };

        size_t bytes;
        read_virtual(
            address,
            &response,
            sizeof( t ),
            &bytes
        );

        return response;
    }

    auto translate_linear(
        uintptr_t directory_base,
        uintptr_t address ) -> uintptr_t {

        directory_base &= ~0xf;

        auto virt_addr = address & ~(~0ul << 12);
        auto pte = ((address >> 12) & (0x1ffll));
        auto pt = ((address >> 21) & (0x1ffll));
        auto pd = ((address >> 30) & (0x1ffll));
        auto pdp = ((address >> 39) & (0x1ffll));
        auto p_mask = ((~0xfull << 8) & 0xfffffffffull);

        size_t readsize = 0;
        uintptr_t pdpe = 0;
        read_physical( directory_base + 8 * pdp, &pdpe, sizeof( pdpe ), &readsize );
        if ( ~pdpe & 1 ) {
            return 0;
        }

        uintptr_t pde = 0;
        read_physical( (pdpe & p_mask) + 8 * pd, &pde, sizeof( pde ), &readsize );
        if ( ~pde & 1 ) {
            return 0;
        }

        /* 1GB large page, use pde's 12-34 bits */
        if ( pde & 0x80 )
            return (pde & (~0ull << 42 >> 12)) + (address & ~(~0ull << 30));

        uintptr_t pteAddr = 0;
        read_physical( (pde & p_mask) + 8 * pt, &pteAddr, sizeof( pteAddr ), &readsize );
        if ( ~pteAddr & 1 ) {
            return 0;
        }

        /* 2MB large page */
        if ( pteAddr & 0x80 ) {
            return (pteAddr & p_mask) + (address & ~(~0ull << 21));
        }

        address = 0;
        read_physical( (pteAddr & p_mask) + 8 * pte, &address, sizeof( address ), &readsize );
        address &= p_mask;

        if ( !address ) {
            return 0;
        }

        return address + virt_addr;
    }

    auto find_min( INT32 g, SIZE_T f ) -> ULONG64
    {
        INT32 h = ( INT32 ) f;
        ULONG64 result = 0;

        result = (((g) < (h)) ? (g) : (h));

        return result;
    }

    auto translate_address( invoke_data* request ) -> driver::status
    {
        translate_invoke data = { 0 };

        if ( !modules::safe_copy(
            &data,
            request->data,
            sizeof( translate_invoke ) ) ) {
            return driver::status::failed_sanity_check;
        }

        if ( !data.virtual_address || !data.directory_base )
            return driver::status::failed_sanity_check;

        auto physical_address = translate_linear(
            data.directory_base,
            data.virtual_address );
        if ( !physical_address ) {
            return driver::status::failed_sanity_check;
        }

        reinterpret_cast< translate_invoke* > (request->data)->physical_address = 
            reinterpret_cast<void*>(physical_address);

        return driver::status::successful_operation;
    }

    auto mm_copy_kernel( invoke_data* request ) -> driver::status
    {
        read_kernel_invoke data = { 0 };
        size_t bytes = 0;

        if ( !modules::safe_copy(
            &data,
            request->data,
            sizeof( read_kernel_invoke ) ) ) {
            return driver::status::failed_sanity_check;
        }

        auto result = STATUS_SUCCESS;

        switch ( data.memory_type ) {

        case MM_COPY_MEMORY_PHYSICAL:
        {
            result = read_physical( 
                data.address, 
                data.buffer, 
                data.size,
                &bytes 
            );

            break;
        }

        case MM_COPY_MEMORY_VIRTUAL:
        {
            result = read_virtual( 
                data.address, 
                data.buffer, 
                data.size, 
                &bytes 
            );

            break;
        }

        default: {
            break;
        }

        }

        if ( !NT_SUCCESS( result ) ) {
            return driver::status::failed_sanity_check;
        }

        return driver::status::successful_operation;
    }

    auto get_dtb( invoke_data* request ) -> driver::status
    {
        dtb_invoke data = { 0 };

        if ( !modules::safe_copy(
            &data,
            request->data,
            sizeof( dtb_invoke ) ) ) {
            return driver::status::failed_sanity_check;
        }

        PEPROCESS process = 0;
        if ( !NT_SUCCESS( qtx_import( PsLookupProcessByProcessId )(
            reinterpret_cast< HANDLE >(data.pid),
            &process) ) ) {

            print_dbg( _(" [sanity] -> get_dtb failed.\n") );
            qtx_import( ObfDereferenceObject )(process);

            return driver::status::failed_sanity_check;
        }

        // 0x28 x64 offset for dtb amd 0x18 for x32 but who the fuck runs on that shitty bit
        uintptr_t process_dtb = read_kernel_virtual<uintptr_t>( (uintptr_t)process + 0x28); /* AMD x64 */
        if ( !process_dtb ) {
            process_dtb = read_kernel_virtual<uintptr_t>( ( uintptr_t ) process + 0x388); /* AMD x32 */
            if (!process_dtb) {
                print_dbg( _(" [sanity] -> get_dtb failed.\n") );
            }
        }

        reinterpret_cast< dtb_invoke* > (request->data)->dtb = process_dtb;

        qtx_import( ObfDereferenceObject )(process);
        return driver::status::successful_operation;
    }

    // now we are acc reading physical,
    // if the read fails the sanity check failed
    auto read_memory( invoke_data* request ) -> driver::status
    {
        read_invoke data = { 0 };

        if ( !modules::safe_copy(
            &data,
            request->data,
            sizeof( read_invoke ) ) ) {
            return driver::status::failed_sanity_check;
        }

        // sometimes does not work
        if ( data.address >= 0x7FFFFFFFFFFF ) {
            return driver::status::failed_sanity_check;
        }

        PEPROCESS process = 0;
        if ( !NT_SUCCESS( qtx_import( PsLookupProcessByProcessId )(
            reinterpret_cast< HANDLE >(data.pid),
            &process) ) ) {
            return driver::status::failed_sanity_check;
        }

        auto physical_address = translate_linear(
            data.dtb,
            data.address );
        if ( !physical_address ) {
            return driver::status::failed_sanity_check;
        }

        auto final_size = find_min(
            PAGE_SIZE - (physical_address & 0xFFF),
            data.size );

        size_t bytes = 0;
        if ( !NT_SUCCESS( read_physical(
            physical_address,
            reinterpret_cast< void* >((reinterpret_cast< ULONG64 >(data.buffer))),
            final_size,
            &bytes ) ) )
        {
            qtx_import( ObfDereferenceObject )(process);
            return driver::status::failed_sanity_check;
        }

        qtx_import( ObfDereferenceObject )(process);
        return driver::status::successful_operation;
    }
}