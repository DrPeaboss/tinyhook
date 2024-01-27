/*******************************************************************************
Copyright (c) 2024 PeaZomboss

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*******************************************************************************/

#include "tinyhook.h"
#include "insn_len.h"

static int GetEntryLen(void* addr)
{
    int len = 0;
    BYTE* p = (BYTE*)addr;
    do {
        len += insn_len((void*)(p + len));
    } while (len < 5);
    return len;
}

#ifdef _CPU_X64
void* TH_GetModulePadding(HMODULE hmodule)
{
    BYTE* p = (BYTE*)hmodule;
    p += ((IMAGE_DOS_HEADER*)p)->e_lfanew + 4; // PE header
    p += sizeof(IMAGE_FILE_HEADER) + ((IMAGE_FILE_HEADER*)p)->SizeOfOptionalHeader; // skip optional
    int sections = ((IMAGE_FILE_HEADER*)p)->NumberOfSections;
    for (int i = 0; i < sections; i++) {
        IMAGE_SECTION_HEADER* psec = (IMAGE_SECTION_HEADER*)p;
        if (memcmp(psec->Name, ".text", 5) == 0) {
            BYTE* offset = (BYTE*)hmodule + psec->VirtualAddress + psec->Misc.VirtualSize;
            offset += 16 - (INT_PTR)offset % 16; // align 16
            return (void*)offset;
        }
        p += sizeof(IMAGE_SECTION_HEADER);
    }
    return NULL;
}
#endif

void TH_Init(TH_Info* info, void* proc, void* fk_proc, void* bridge)
{
    BYTE hook_jump[8];
    memcpy(hook_jump, proc, 8);
    info->proc = proc;
    info->old_entry = *(LONG64*)&hook_jump;
#ifdef _CPU_X64
    DWORD old_bridge;
    BYTE jump_pattern[14] = { 0x68,0,0,0,0,0xC7,0x44,0x24,0x04,0,0,0,0,0xC3 };
    UINT_PTR uiptr = (UINT_PTR)fk_proc;
    *(DWORD*)&jump_pattern[1] = (DWORD)uiptr;
    *(DWORD*)&jump_pattern[9] = (DWORD)(uiptr >> 32);
    VirtualProtect(bridge, 14, PAGE_EXECUTE_READWRITE, &old_bridge);
    memcpy(bridge, jump_pattern, 14);
    VirtualProtect(bridge, 14, old_bridge, &old_bridge);
    *(DWORD*)&hook_jump[1] = (DWORD)((char*)bridge - (char*)proc - 5);
#endif
#ifdef _CPU_X86
    *(DWORD*)&hook_jump[1] = (char*)fk_proc - (char*)proc - 5;
#endif
    hook_jump[0] = 0xE9;
    info->hook_jump = *(LONG64*)&hook_jump;
}

void TH_Hook(TH_Info* info)
{
    DWORD old;
    VirtualProtect(info->proc, 8, PAGE_EXECUTE_READWRITE, &old);
    InterlockedCompareExchange64((volatile LONG64*)info->proc, info->hook_jump, info->old_entry);
    VirtualProtect(info->proc, 8, old, &old);
}

void TH_Unhook(TH_Info* info)
{
    DWORD old;
    VirtualProtect(info->proc, 8, PAGE_EXECUTE_READWRITE, &old);
    InterlockedCompareExchange64((volatile LONG64*)info->proc, info->old_entry, info->hook_jump);
    VirtualProtect(info->proc, 8, old, &old);
}

static inline void* SkipFF25(void* proc)
{
    DWORD offset = *(DWORD*)((BYTE*)proc + 2);
#ifdef _CPU_X64
    return *(void**)((BYTE*)proc + offset + 6);
#endif
#ifdef _CPU_X86
    return *(void**)offset;
#endif
}

void TH_GetDetour(TH_Info* info, void** detour)
{
    DWORD old;
    VirtualProtect(info->detour, 32, PAGE_EXECUTE_READWRITE, &old);
    int entry_len;
    void* detour_to;
    WORD* pentry = info->proc;
    if (*pentry == 0x25FF) {
        entry_len = 0;
        detour_to = SkipFF25(pentry);
    }
    else {
        entry_len = GetEntryLen(info->proc);
        memcpy(info->detour, info->proc, entry_len);
        detour_to = (char*)info->proc + entry_len;
    }
#ifdef _CPU_X64
    BYTE jump_pattern[14] = { 0x68,0,0,0,0,0xC7,0x44,0x24,0x04,0,0,0,0,0xC3 };
    UINT_PTR uiptr = (UINT_PTR)detour_to;
    *(DWORD*)&jump_pattern[1] = (DWORD)uiptr;
    *(DWORD*)&jump_pattern[9] = (DWORD)(uiptr >> 32);
    memcpy(&info->detour[entry_len], jump_pattern, 14);
#endif
#ifdef _CPU_X86
    BYTE jump_pattern[5] = { 0xE9,0,0,0,0 };
    *(DWORD*)&jump_pattern[1] = (char*)detour_to - (char*)&info->detour - 5;
    memcpy(&info->detour[entry_len], jump_pattern, 5);
#endif
    *detour = (void*)info->detour;
}
