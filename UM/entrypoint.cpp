#define ENTRYPOINT_CPP

#include "imports.h"

INT APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE, PSTR, INT nCmdShow)
{
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);

    Sleep(500);
    auto result = request->initialize_handle();
    if (!result)
    {
        /* Load Driver - No Handle */
        result = request->initialize_handle();
    }
    
    request->unlinkprocess();

    std::cout << "Press F5 Once in menu...\n";
    while (!GetAsyncKeyState(VK_F5) & 1);

	const auto pid = request->get_process_pid( L"escapefromtarkov.exe" );
    if (pid == NULL) exit(0);
    auto ret = request->attach(pid);
    if (ret == NULL) exit(0);
	auto base_address = request->get_image_base( nullptr );
    if (base_address == NULL) exit(0);
    result = request->get_cr3(base_address);

}