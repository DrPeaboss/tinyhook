#include <Windows.h>
#include <stdio.h>
#include "tinyhook.h"

HWND(WINAPI *dt_GetForegroundWindow) (void);
int (WINAPI *dt_MessageBoxA) (HWND, LPCSTR, LPCSTR, UINT);

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

TH_Info hook_gfw;
TH_Info hook_mba;

int main()
{
    int i = 0;
    HMODULE h_user32 = GetModuleHandleA("user32.dll");
#ifdef _CPU_X86
    TH_Init(&hook_gfw, GetProcAddress(h_user32, "GetForegroundWindow"), fk_GetForegroundWindow, NULL);
    TH_Init(&hook_mba, GetProcAddress(h_user32, "MessageBoxA"), fk_MessageBoxA, NULL);
#endif
#ifdef _CPU_X64
    char* padding = TH_GetModulePadding(h_user32);
    TH_Init(&hook_gfw, GetProcAddress(h_user32, "GetForegroundWindow"), fk_GetForegroundWindow, padding);
    TH_Init(&hook_mba, GetProcAddress(h_user32, "MessageBoxA"), fk_MessageBoxA, padding + 16);
#endif
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
}
