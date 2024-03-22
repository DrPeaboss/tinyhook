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

#pragma once

#include <Windows.h>

#if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64) || defined(_M_AMD64)
#define _CPU_X64
#elif defined(__i386__) || defined(_M_IX86)
#define _CPU_X86
#elif defined(__aarch64__) || defined(_M_ARM64)
#define _CPU_ARM64
#else
#error "Unsupported CPU"
#endif

typedef struct th_info
{
    BYTE detour[32];
    void* proc;
#if defined(_CPU_X64) || defined(_CPU_X86)
    LONG64 hook_jump;
    LONG64 old_entry;
#elif defined(_CPU_ARM64)
    long hook_jump;
    long old_entry;
#endif
} TH_Info;

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_CPU_X64) || defined(_CPU_ARM64)
/* get the padding zone in the .text section of a module
* @param hmodule: the module handle
* @return pointer to the padding zone which align 16
*/
void* TH_GetModulePadding(HMODULE hmodule);
#endif

/* initialize a TH_Info struct, if do not mind speed, use TH_EasyInit is easier
* @param info: the instance of TH_Info struct
* @param proc: the procedure to hook
* @param fk_proc: the fake procedure
* @param bridge: the bridge memory used by x64(+-2GB) and ARM64(+-128MB), x86 will be ignored
*/
void TH_Init(TH_Info* info, void* proc, void* fk_proc, void* bridge);

/* initialize and get detour automatically
* @param info: instance
* @param proc: proc to hook
* @param fk_proc: fake proc
* @param detour: pointer to the detour proc
*/
void TH_EasyInit(TH_Info* info, void* proc, void* fk_proc, void** detour);

/* hook the procedure
* @param info: the TH_Info instance
*/
void TH_Hook(TH_Info* info);

/* unhook the procedure
* @param info: the TH_Info instance
*/
void TH_Unhook(TH_Info* info);

/* get the detour to call the original procedure, must call TH_Init first
* @param info: the TH_Info instance
* @param detour: pointer to the detour entry pointer
*/
void TH_GetDetour(TH_Info* info, void** detour);

#ifdef __cplusplus
}
#endif
