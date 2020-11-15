#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: inject.exe <pid> <dll_path>\n");
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    if (!pid) {
        printf("Error: first argument is not a valid pid\n");
        return 1;
    }

    HANDLE h_target = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (!pid) {
        printf("Error: failed to open process with ID %i.\n", pid);
        return 1;
    }

    char *dll_path = argv[2];
    SIZE_T path_len = strlen(dll_path);

    char *remote_dll_path = VirtualAllocEx(h_target, NULL, path_len+1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pid) {
        printf("Error: failed to allocate memory for path.\n");
        return 1;
    }

    SIZE_T written = 0;
    WriteProcessMemory(h_target, remote_dll_path, dll_path, path_len+1, &written);
    if (written != (path_len+1)) {
        printf("Error: failed to write path. %i bytes written, wanted %i.\n", written, (path_len+1));
        return 1;
    }

    HANDLE h_k32 = GetModuleHandleA("kernel32.dll");
    HANDLE h_load_library = GetProcAddress(h_k32, "LoadLibraryA");

    DWORD thread_id;
    HANDLE thread = CreateRemoteThread(h_target, NULL, 0, h_load_library, remote_dll_path, 0, &thread_id);
    if (!thread) {
        printf("Error: failed to create remote thread\n");
        return 1;
    }

    WaitForSingleObject((HANDLE)thread_id, INFINITE);

    DWORD library_handle;
    GetExitCodeThread((HANDLE)thread_id, &library_handle);
    if (!library_handle) {
        printf("Error: LoadLibrary call in remote thread returned NULL\n");
        return 1;
    }

    printf("DLL injected successfully.\n");
    return 0;
}