#include <Windows.h>
#include <stdio.h>
#include "tinyhook.h"

HWND(WINAPI *dt_GetForegroundWindow) (void);
int (WINAPI *dt_MessageBoxA) (HWND, LPCSTR, LPCSTR, UINT);
BOOL(WINAPI *dt_MessageBeep) (UINT);

HWND WINAPI fk_GetForegroundWindow()
{
    printf("Change %d to %d\n", (int)dt_GetForegroundWindow(), 123456);
    return (HWND)123456;
}

int WINAPI fk_MessageBoxA(HWND hwnd, LPCSTR text, LPCSTR title, UINT flags)
{
    printf("%s: %s\n", title, text);
    return dt_MessageBoxA(hwnd, "Hooked!", "ERROR", MB_ICONERROR | MB_TOPMOST);
}

BOOL WINAPI fk_MessageBeep(UINT utype)
{
    printf("Change Beep type %d to %d\n", utype, MB_ICONSTOP);
    return dt_MessageBeep(MB_ICONSTOP);
}

TH_Info hook_gfw;
TH_Info hook_mba;
TH_Info hook_mbp;

int main()
{
    int i = 0;
    HMODULE h_user32 = GetModuleHandleA("user32.dll");
#ifdef _CPU_X86
    // For x86, it is simple
    TH_Init(&hook_gfw, GetProcAddress(h_user32, "GetForegroundWindow"), fk_GetForegroundWindow, NULL);
    TH_Init(&hook_mba, GetProcAddress(h_user32, "MessageBoxA"), fk_MessageBoxA, NULL);
#else
    // If not x86, manually get padding memory as bridge
    char* padding = TH_GetModulePadding(h_user32);
    printf("padding addr 0x%llx\n", (LONG64)padding);
    DWORD old_protect;
    // Make sure the memory is writable
    VirtualProtect(padding, 16, PAGE_EXECUTE_READWRITE, &old_protect);
    TH_Init(&hook_gfw, GetProcAddress(h_user32, "GetForegroundWindow"), fk_GetForegroundWindow, padding);

    // Or use TH_SearchZeroAround
    void* proc_mba = GetProcAddress(h_user32, "MessageBoxA");
    char* padding2 = TH_SearchZeroAround(proc_mba, 16);
    printf("padding2 addr 0x%llx\n", (LONG64)padding2);
    VirtualProtect(padding2, 16, PAGE_EXECUTE_READWRITE, &old_protect);
    TH_Init(&hook_mba, proc_mba, fk_MessageBoxA, padding2);
#endif
    // Don't forget if using TH_Init
    TH_GetDetour(&hook_gfw, (void**)&dt_GetForegroundWindow);
    TH_GetDetour(&hook_mba, (void**)&dt_MessageBoxA);
    TH_Hook(&hook_gfw);
    printf("Fake GetForegroundWindow: %d\n", (int)GetForegroundWindow());
    TH_Unhook(&hook_gfw);
    printf("Real GetForegroundWindow: %d\n", (int)GetForegroundWindow());
    TH_Hook(&hook_mba);
    MessageBoxA(NULL, "Hello, World!", "Title", 0);
    TH_Unhook(&hook_mba);
    MessageBoxA(NULL, "Not hooked.", "hmm", 0);
    // Use TH_EasyInit for any CPU target, it is automatically done
    TH_EasyInit(&hook_mbp, GetProcAddress(h_user32, "MessageBeep"), fk_MessageBeep, (void**)&dt_MessageBeep);
    TH_Hook(&hook_mbp);
    Sleep(1000);
    printf("Fake Beeping...\n");
    MessageBeep(MB_OK);
    Sleep(1000);
    TH_Unhook(&hook_mbp);
    printf("Real Beeping...\n");
    MessageBeep(MB_OK);
    Sleep(1000);
}
