namespace request
{
    _declspec(noinline) NTSTATUS write_memory( invoke_data* request )
    {
        write_invoke data = { 0 };

        NTSTATUS out = 0;

        if (!modules::safe_copy( &data, request->data, sizeof( write_invoke ) ))
            return 0;

        if (!data.address || !data.pid || !data.buffer || !data.size || data.address >= 0x7FFFFFFFFFFF )
            return 0;

        PEPROCESS process = 0;
        if (!NT_SUCCESS( qtx_import(PsLookupProcessByProcessId)( (HANDLE)data.pid, &process ) ))
        {
            return driver::status::failed_sanity_check;
        }

        //if ( data.address >= 0x7FFFFFFFFFFF /*|| data.phys*/ )
        //{
        //    ULONGLONG process_base = physical_memory_operations::get_process_cr3( process );

        //    imports::obf_dereference_object( process );

        //    SIZE_T this_offset = NULL;
        //    SIZE_T total_size = data.size;

        //    INT64 physical_address = physical_memory_operations::translate_linear( process_base, ( ULONG64 ) data.address + this_offset );
        //    if ( !physical_address )
        //        return STATUS_UNSUCCESSFUL;

        //    ULONG64 final_size = physical_memory_operations::find_min( PAGE_SIZE - (physical_address & 0xFFF), total_size );
        //    SIZE_T bytes_trough = NULL;

        //    physical_memory_operations::write( PVOID( physical_address ), ( PVOID ) ((ULONG64) reinterpret_cast< write_invoke* >(request->data)->buffer + this_offset), final_size, &bytes_trough );
        //    return out;
        //}

       // printf( "mmcopyvirt: cp, %llx, pid %i, addr %llx, size %i\n", reinterpret_cast<write_invoke*>(request->data)->buffer, data.pid, data.address, data.size);
        size_t bytes = 0;
        if (qtx_import(MmCopyVirtualMemory)(
            qtx_import(IoGetCurrentProcess)( ), 
            (void*)reinterpret_cast<write_invoke*>(request->data)->buffer, 
            process, 
            (void*)data.address,
            data.size,
            UserMode,
            &bytes ) != STATUS_SUCCESS || bytes != data.size)
        {
            qtx_import(ObfDereferenceObject)( process );
            return driver::status::failed_sanity_check;
        }

        qtx_import( ObfDereferenceObject )(process);

        return out;
    }
}