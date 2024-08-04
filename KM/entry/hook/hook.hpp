_declspec(noinline) auto manual_mapped_entry(
	PDRIVER_OBJECT driver_obj,
	PUNICODE_STRING registry_path) -> long
{
	UNREFERENCED_PARAMETER(registry_path);

	/* Please use custom shellcode/asm for the Hook, This can be signature scanned by BE / EAC */
	uint8_t execute[] = {

		0x48, 0xB8, // -> mov, rax
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // -> address
		0xFF, 0xE0 // -> jmp rax

	};

	*reinterpret_cast<void**>(&execute[2]) = &vortex::io_dispatch;
	if (!NT_SUCCESS(modules::write_address(globals::entry_point, execute, sizeof(execute), true)))
		return driver::status::failed_sanity_check;

	*reinterpret_cast<void**>(&execute[2]) = &vortex::io_close;
	auto create_close = (globals::cave_base + sizeof(execute));
	if (!NT_SUCCESS(modules::write_address(create_close, execute, sizeof(execute), true)))
		return driver::status::failed_sanity_check;

	UNICODE_STRING device;
	UNICODE_STRING dos_device;

	qtx_import(RtlInitUnicodeString)(&device, _(DEVICE_NAME));
	qtx_import(RtlInitUnicodeString)(&dos_device, _(DOS_NAME));

	PDEVICE_OBJECT device_obj = nullptr;
	auto status = qtx_import(IoCreateDevice)(driver_obj,
		0,
		&device,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		false,
		&device_obj);

	if (NT_SUCCESS(status))
	{
		SetFlag(driver_obj->Flags, DO_BUFFERED_IO);

		driver_obj->MajorFunction[IRP_MJ_CREATE] = reinterpret_cast<PDRIVER_DISPATCH>(&vortex::io_close);
		driver_obj->MajorFunction[IRP_MJ_CLOSE] = reinterpret_cast<PDRIVER_DISPATCH>(&vortex::io_close);
		driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = reinterpret_cast<PDRIVER_DISPATCH>(globals::entry_point);
		driver_obj->DriverUnload = nullptr;

		ClearFlag(device_obj->Flags, DO_DIRECT_IO);
		ClearFlag(device_obj->Flags, DO_DEVICE_INITIALIZING);

		status = qtx_import(IoCreateSymbolicLink)(&dos_device, &device);
		if (!NT_SUCCESS(status)) {
			qtx_import(IoDeleteDevice)(device_obj);
		}

	}

	return status;
}

_declspec(noinline) auto initialize_hook() -> driver::status
{

	globals::ntos_image_base = modules::get_ntos_base_address();
	if (!globals::ntos_image_base) {
		print_dbg(_(" [sanity] -> failed to get ntoskrnl image.\n"));
		return driver::status::failed_sanity_check;
	}

	auto io_create_driver_t = reinterpret_cast<void*>(modules::get_kernel_export(globals::ntos_image_base, _("IoCreateDriver")));
	if (!io_create_driver_t) {
		print_dbg(_(" [sanity] -> failed to get IoCreateDriver.\n"));
		return driver::status::failed_sanity_check;
	}

	*reinterpret_cast<void**>(&globals::io_create_driver) = io_create_driver_t;

	/*
	const auto random = modules::get_random( );
	switch ( random % 2 )
	{
	case 0:
		break;
	case 1:
		break;
	}*/

	const auto target_module = modules::get_kernel_module(_("")); /* Find your own module that is not PG Protected */
	if (!target_module) {
		print_dbg(_(" [sanity] -> failed to find target module.\n"));
		return driver::status::failed_sanity_check;
	}

	BYTE section_char[] = { '.', 't', 'e', 'x', 't', '\0' };
	globals::cave_base = modules::find_pattern(target_module,
		_(""), /* Find your own Signature */
		_("")); /* Find your own Mask */

	// get code cave a different way please
	globals::cave_base = globals::cave_base - 0x30;

	crt::kmemset(&section_char, 0, sizeof(section_char));

	/* Please use custom shellcode/asm for the Hook, This can be signature scanned by BE / EAC */
	uint8_t execute[] = {

		0x48, 0xB8, // -> mov, rax
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // -> address
		0xFF, 0xE0 // -> jmp rax

	};

	globals::entry_point = globals::cave_base;

	*reinterpret_cast<void**>(&execute[2]) = &manual_mapped_entry;
	modules::write_address(
		globals::entry_point,
		execute,
		sizeof(execute),
		true
	);

	return driver::status::successful_operation;
}

_declspec(noinline) auto initialize_ioctl() -> driver::status
{

	/////////////// Original Function QWORD
	const auto result = globals::io_create_driver(
		nullptr,
		reinterpret_cast<DRIVER_INITIALIZE*>(globals::entry_point)
	);
	if (!NT_SUCCESS(result)) {
		return driver::status::failed_sanity_check;
	}

	return driver::status::successful_operation;
}