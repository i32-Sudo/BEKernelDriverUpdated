namespace request
{
	_declspec(noinline) driver::status virtual_allocate(invoke_data* request)
	{
		palloc_invoke data = { 0 };

		if (!modules::safe_copy(&data, request->data, sizeof(base_invoke)))
			return driver::status::failed_sanity_check;

		DWORD protection_old = 0;
		if (ZwAllocateVirtualMemory(NtCurrentProcess(), reinterpret_cast<LPVOID*>(data->address), data->dwSize, nullptr, data->flAllocationType, protection_old) != STATUS_SUCCESS)
			return driver::status::failed_sanity_check;

		return driver::status::successful_operation;
	}
}