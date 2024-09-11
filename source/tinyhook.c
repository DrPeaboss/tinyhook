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

#if defined(_CPU_X86) || defined(_CPU_X64)

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

#elif defined(_CPU_ARM64)

#define LDR_X17_NEXT2 0x58000051 // LDR X17, [PC + #8]
#define BR_X17        0xD61F0220 // BR X17
#define LONG_JUMP_X17 ((LONG64)BR_X17 << 32 | LDR_X17_NEXT2)
#define LDR_REG_NEXT2 0x58000040 // LDR Xn, [PC + #8]
#define B_NEXT3       0x14000003 // B [PC + #12]

#endif

#if defined(_CPU_X64) || defined(_CPU_ARM64)
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

static inline void* FindModuleBase(void* proc)
{
    BYTE* p = (BYTE*)((INT_PTR)proc & 0xFFFFFFFFFFFF0000);
    while (p[0] != 'M' && p[1] != 'Z')
        p -= 0x10000;
    return p;
}
#endif

void TH_Init(TH_Info* info, void* proc, void* fk_proc, void* bridge)
{
    info->proc = proc;
#if defined(_CPU_X64) || defined(_CPU_X86)
    BYTE hook_jump[8];
    memcpy(hook_jump, proc, 8);
    info->old_entry = *(LONG64*)&hook_jump;
#ifdef _CPU_X64
    BYTE jump_pattern[14] = { 0xFF,0x25,0,0,0,0,0,0,0,0,0,0,0,0 };
    *(void**)&jump_pattern[6] = fk_proc;
    memcpy(bridge, jump_pattern, 14);
    *(DWORD*)&hook_jump[1] = (DWORD)((char*)bridge - (char*)proc - 5);
#endif
#ifdef _CPU_X86
    *(DWORD*)&hook_jump[1] = (char*)fk_proc - (char*)proc - 5;
#endif
    hook_jump[0] = 0xE9;
    info->hook_jump = *(LONG64*)&hook_jump;
#elif defined(_CPU_ARM64)
    DWORD hook_jump = 0x14000000;
    info->old_entry = *(long*)proc;
    *(LONG64*)bridge = LONG_JUMP_X17;
    *((LONG64*)bridge + 1) = (LONG64)fk_proc;
    hook_jump |= (long)((long*)bridge - (long*)proc) & 0x3FFFFFF;
    info->hook_jump = hook_jump;
#endif
}

void TH_EasyInit(TH_Info* info, void* proc, void* fk_proc, void** detour)
{
#if defined(_CPU_X86)
    TH_Init(info, proc, fk_proc, NULL);
    TH_GetDetour(info, detour);
#elif defined(_CPU_X64) || defined(_CPU_ARM64)
    LONG64* padding = TH_GetModulePadding(FindModuleBase(proc));
    while (padding[0] != 0 || padding[1] != 0)
        padding += 2;
    DWORD old_bridge_protect;
    VirtualProtect(padding, 16, PAGE_EXECUTE_READWRITE, &old_bridge_protect);
    TH_Init(info, proc, fk_proc, padding);
    VirtualProtect(padding, 16, old_bridge_protect, &old_bridge_protect);
    if (detour)
        TH_GetDetour(info, detour);
#endif
}

void TH_Hook(TH_Info* info)
{
    DWORD old;
#if defined(_CPU_X64) || defined(_CPU_X86)
    VirtualProtect(info->proc, 8, PAGE_EXECUTE_READWRITE, &old);
    InterlockedCompareExchange64((volatile LONG64*)info->proc, info->hook_jump, info->old_entry);
    VirtualProtect(info->proc, 8, old, &old);
#elif defined(_CPU_ARM64)
    VirtualProtect(info->proc, 4, PAGE_EXECUTE_READWRITE, &old);
    InterlockedCompareExchange((volatile long*)info->proc, info->hook_jump, info->old_entry);
    VirtualProtect(info->proc, 4, old, &old);
#endif
}

void TH_Unhook(TH_Info* info)
{
    DWORD old;
#if defined(_CPU_X64) || defined(_CPU_X86)
    VirtualProtect(info->proc, 8, PAGE_EXECUTE_READWRITE, &old);
    InterlockedCompareExchange64((volatile LONG64*)info->proc, info->old_entry, info->hook_jump);
    VirtualProtect(info->proc, 8, old, &old);
#elif defined(_CPU_ARM64)
    VirtualProtect(info->proc, 4, PAGE_EXECUTE_READWRITE, &old);
    InterlockedCompareExchange((volatile long*)info->proc, info->old_entry, info->hook_jump);
    VirtualProtect(info->proc, 4, old, &old);
#endif
}

void TH_GetDetour(TH_Info* info, void** detour)
{
    DWORD old;
    VirtualProtect(info->detour, 32, PAGE_EXECUTE_READWRITE, &old);
#if defined(_CPU_X64) || defined(_CPU_X86)
    int entry_len;
    void* detour_to;
    BYTE* pentry = info->proc;
    if (*(WORD*)pentry == 0x25FF) {
        entry_len = 0;
        detour_to = SkipFF25(pentry);
    }
#ifdef _CPU_X64
    else if (*pentry == 0x48 && *(WORD*)(pentry + 1) == 0x25FF) {
        entry_len = 0;
        detour_to = SkipFF25(pentry + 1);
    }
#endif
    else {
        entry_len = GetEntryLen(info->proc);
        memcpy(info->detour, info->proc, entry_len);
        detour_to = (char*)info->proc + entry_len;
    }
#ifdef _CPU_X64
    BYTE jump_pattern[14] = { 0xFF,0x25,0,0,0,0,0,0,0,0,0,0,0,0 };
    *(void**)&jump_pattern[6] = detour_to;
    memcpy(&info->detour[entry_len], jump_pattern, 14);
#endif
#ifdef _CPU_X86
    BYTE jump_pattern[5] = { 0xE9,0,0,0,0 };
    *(DWORD*)&jump_pattern[1] = (char*)detour_to - (char*)&info->detour - entry_len - 5;
    memcpy(&info->detour[entry_len], jump_pattern, 5);
#endif
#elif defined(_CPU_ARM64)
    DWORD* insn = (DWORD*)info->proc;
    void* detour_to = insn + 1;
    DWORD* pdetour = (DWORD*)info->detour;
    if (*insn >> 26 == 5) { // B imm with +- 128MB offset
        int diff = *insn & 0x3FFFFFF;
        if (diff & 0x2000000) // check negative
            diff |= 0xFC000000;
        detour_to = insn + diff;
    }
    else if ((*insn & 0x9F000000) == 0x90000000) { // ADRP Xn, PC+imm with +- 4GB offset
        DWORD imm = ((*insn >> 29) & 3) | ((*insn >> 3) & 0xFFFFC);
        void* addr = (void*)(((LONG64)insn & 0xFFFFFFFFFFFFF000) + ((LONG64)imm << 12));
        if (insn[1] >> 22 == 0x3E5) { // LDR Xm, [Xn, #pimm]
            int pimm = ((insn[1] >> 10) & 0xFFF) * 8;
            detour_to = *(void**)((BYTE*)addr + pimm);
        }
        // not sure with this branch
        else if (insn[1] >> 22 == 0x284) { // ADD Xm, Xn, #imm12
            int imm12 = (insn[1] >> 10) & 0xFFF;
            detour_to = (BYTE*)addr + imm12;
        }
        else { // normal ADRP like MessageBoxA
            *pdetour++ = LDR_REG_NEXT2 | (*insn & 31);
            *pdetour++ = B_NEXT3;
            *(void**)pdetour = addr;
            pdetour += 2;
        }
    }
    else {
        *pdetour++ = *insn;
    }
    *(LONG64*)pdetour = LONG_JUMP_X17;
    *(void**)(pdetour + 2) = detour_to;
#endif
    *detour = (void*)info->detour;
}
