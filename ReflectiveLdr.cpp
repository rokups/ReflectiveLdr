//
// Copyright (c) 2012-2017 ReflectiveLdr contributors (see COPYRIGHT.md)
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted
// provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice, this list of
// conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright notice, this list of
// conditions and the following disclaimer in the documentation and/or other materials provided
// with the distribution.
//
//     * Neither the name of copyright holder nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
#include <stdio.h>
#include "ReflectiveLdr.h"
#include "ReflectiveLdr_p.h"


namespace Reflective
{

inline void LDR_LOG(const char* format, ...)
{
#if 0
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
    fflush(stderr);
#endif
}

char chrtoupper_i(char c)
{
    if (c >= 'a' && c <= 'z')
        c -= 'a' - 'A';
    return c;
}

void toupper_i(char* str)
{
    while (*str)
        *str++ = chrtoupper_i(*str);
}

int stricmp_i(const char* a, const char* b, size_t n)
{
    char ca, cb;
    for (;;)
    {
        ca = chrtoupper_i(*a);
        cb = chrtoupper_i(*b);

        if (ca != cb || (n > 0 && --n == 0))
            return ca - cb;

        if (ca == 0)
            return 0;

        a++;
        b++;
    }
}

int strcmp_i(const char* a, const char* b, size_t n)
{
    char ca, cb;
    for (;;)
    {
        ca = *a;
        cb = *b;
        if (ca != cb || (n > 0 && --n == 0))
            return ca - cb;

        if (ca == 0)
            return 0;

        a++;
        b++;
    }
}

DWORD hashW(PUNICODE_STR string)
{
    PBYTE c = (PBYTE)string->pBuffer;
    DWORD length = string->Length;
    DWORD hash = 0;

    do
    {
        hash = ror((DWORD)hash);
        hash += chrtoupper_i(*c);
        c++;
    } while (--length);
    return hash;
}

void memcpy_i(void* dest, const void* src, size_t len)
{
    PBYTE pDest = (PBYTE)dest;
    PBYTE pSrc = (PBYTE)src;
    while (len--)
        *pDest++ = *(BYTE*)pSrc++;
}

char* strcpy_i(char* dest, const char* src, size_t n)
{
    while (*src)
    {
        if (n > 0 && --n == 0)
            break;
        *dest++ = *src++;
    }
    *dest = 0;
    return ++dest;
}

void memset_i(void* dest, BYTE b, size_t len)
{
    PBYTE pDest = (PBYTE)dest;
    while (len--)
        *pDest++ = b;
}

size_t strlen_i(const char* str)
{
    size_t len = 0;
    for (; str[len] != 0; len++);
    return len;
}
#if !__GNUC__
#   pragma intrinsic( _ReturnAddress )
#endif
// This function can not be inlined by the compiler or we will not get the address we expect. Ideally
// this code will be compiled with the /O2 and /Ob1 switches. Bonus points if we could take advantage of
// RIP relative addressing in this instance but I dont believe we can do so with the compiler intrinsics
// available (and no inline asm available under x64).
__declspec(noinline) ULONG_PTR caller(VOID)
{
#if __GNUC__
    return (ULONG_PTR)__builtin_return_address(0);
#else
    return (ULONG_PTR)_ReturnAddress();
#endif
}

Ldr::Ldr() : _api(0)
{
    InitializeListHead(&_reflectiveModules);
    InitializeListHead(&_importAlternatives);
    InitializeListHead(&_cachedModules);
    LoadApi();
}

Ldr::~Ldr()
{
    while(_reflectiveModules.Flink != &_reflectiveModules)
    {
        ReflectiveModule* m = (ReflectiveModule*)_reflectiveModules.Flink;
        RemoveEntryList(m);
        dealloc(m);
    }

    while(_importAlternatives.Flink != &_importAlternatives)
    {
        ImportMapping* m = (ImportMapping*)_importAlternatives.Flink;
        RemoveEntryList(m);
        dealloc(m);
    }

    while(_cachedModules.Flink != &_cachedModules)
    {
        CachedModule* m = (CachedModule*)_cachedModules.Flink;
        dealloc(m->pImage);
        RemoveEntryList(m);
        dealloc(m);
    }

    dealloc(_api);
    _api = 0;
}

const char* Ldr::GetOriginalImageName(PVOID bpBase)
{
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)bpBase;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)bpBase + pDosHdr->e_lfanew);
    if (!pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
        return 0;

    auto pRefExp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)bpBase +
        pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    return (const char*)((PBYTE)bpBase + pRefExp->Name);
}

// We implement a minimal GetProcAddress to avoid using the native kernel32!GetProcAddress which
// wont be able to resolve exported addresses in reflectivly loaded librarys.
FARPROC Ldr::GetProcAddressR(HMODULE hModule, LPCSTR lpProcName)
{
    PBYTE bpBase = (PBYTE)hModule;
    FARPROC fpResult = NULL;

    if (hModule == NULL)
        return NULL;

#if !__GNUC__
    __try
#endif
    {
        PDWORD dwpAddressArray = 0;
        PDWORD dwpNameArray = 0;
        PWORD wpNameOrdinals = 0;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(bpBase + ((PIMAGE_DOS_HEADER)bpBase)->e_lfanew);
        PIMAGE_DATA_DIRECTORY pDataDirectory =
                (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(bpBase + pDataDirectory->VirtualAddress);

        dwpAddressArray = (PDWORD)(bpBase + pExportDirectory->AddressOfFunctions);
        dwpNameArray = (PDWORD)(bpBase + pExportDirectory->AddressOfNames);
        wpNameOrdinals = (PWORD)(bpBase + pExportDirectory->AddressOfNameOrdinals);

        // test if we are importing by name or by ordinal...
        if (((size_t)lpProcName & 0xFFFF0000) == 0x00000000)
        {
            // import by ordinal...
            // use the import ordinal (- export ordinal base) as an index into the array of addresses
            fpResult = (FARPROC)(bpBase + dwpAddressArray[(IMAGE_ORDINAL((size_t)lpProcName) - pExportDirectory->Base)]);
        }
        else
        {
            // import by name...
            DWORD dwCounter = pExportDirectory->NumberOfNames;
            while (dwCounter--)
            {
                char* cpExportedFunctionName = (char*)(bpBase + *dwpNameArray);

                // test if we have a match...
                if (strcmp_i(cpExportedFunctionName, lpProcName) == 0)
                {
                    // use the functions name ordinal as an index into the array of name pointers
                    DWORD va = dwpAddressArray[*wpNameOrdinals];
                    fpResult = (FARPROC)(bpBase + va);      // Normal import.
                    if (va >= pDataDirectory->VirtualAddress &&
                        va <= (pDataDirectory->VirtualAddress + pDataDirectory->Size))
                    {
                        // Forwarded import.
                        char module[128];
                        char procedure[128];
                        strcpy_i(module, (const char*)fpResult, sizeof(module));

                        // Find a first dot which idicates end of of module name.
                        int i = 0; for (; module[i] != '.'; i++); i++;
                        // Copy anything after dot to `procedure`.
                        strcpy_i(procedure, &module[i], sizeof(procedure));
                        // Append .dll suffix because reflective loader tracks modules by full name.
                        array_string(dll_suffix, "dll");
                        strcpy_i(&module[i], dll_suffix, sizeof(module) - i);

                        HMODULE hModuleFwd = this->LoadLibrary(module);
                        if (hModuleFwd)
                            fpResult = this->GetProcAddress(hModuleFwd, procedure);
                    }
                    break;
                }

                dwpNameArray++;
                wpNameOrdinals++;
            }
        }
    }
#if !__GNUC__
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        fpResult = NULL;
    }
#endif

    return fpResult;
}

// This is our position independent reflective DLL loader/injector
HMODULE Ldr::MapImageAndExecute(LPCVOID lpImage, LPVOID lpParameter)
{
    // STEP 2: load our image into a new permanent location in memory...

    // get the VA of the NT Header for the PE to be loaded
    auto pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)lpImage + ((PIMAGE_DOS_HEADER)lpImage)->e_lfanew);

    // allocate all the memory for the DLL to be loaded into. we can load at any address because we will
    // relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
    auto pbNewBase = (PBYTE)alloc(pNtHdr->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);

    // we must now copy over the headers
    memcpy_i(pbNewBase, lpImage, pNtHdr->OptionalHeader.SizeOfHeaders);
    pNtHdr = (PIMAGE_NT_HEADERS)(pbNewBase + ((PIMAGE_DOS_HEADER)pbNewBase)->e_lfanew);

    // STEP 3: load in all of our sections...
    auto pSection = ((PIMAGE_SECTION_HEADER)((PBYTE)&pNtHdr->OptionalHeader + pNtHdr->FileHeader.SizeOfOptionalHeader));
    for (WORD i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++, pSection++)
        memcpy_i(pbNewBase + pSection->VirtualAddress, (PBYTE)lpImage + pSection->PointerToRawData,
                 pSection->SizeOfRawData);

    // STEP 4: process our images import table...
    if (pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        auto pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pbNewBase +
            pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        // iterate through all imports
        while (pImport->Name)
        {
            auto cpLibraryName = (LPCSTR)(pbNewBase + pImport->Name);
            PBYTE bpDepBase = 0;

            bpDepBase = (PBYTE)LoadLibrary(cpLibraryName);

            if (bpDepBase)
            {
                auto pThunkOrig = (PIMAGE_THUNK_DATA)(pbNewBase + pImport->OriginalFirstThunk);
                auto pThunkFirst = (PIMAGE_THUNK_DATA)(pbNewBase + pImport->FirstThunk);
                auto pNtHdrDep = (PIMAGE_NT_HEADERS)(bpDepBase + ((PIMAGE_DOS_HEADER)bpDepBase)->e_lfanew);

                // iterate through all imported functions, importing by ordinal if no name present
                while (pThunkFirst->u1.Function)
                {
                    if (pThunkOrig && (pThunkOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG))
                    {
                        auto exportDir = (PIMAGE_EXPORT_DIRECTORY)(bpDepBase +
                            pNtHdrDep->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                        auto addressArray = (PDWORD)(bpDepBase + exportDir->AddressOfFunctions);
                        pThunkFirst->u1.Function =
                            (UINT_PTR)(bpDepBase + addressArray[IMAGE_ORDINAL(pThunkOrig->u1.Ordinal) - exportDir->Base]);
                    }
                    else
                    {
                        auto cpName = (LPCSTR)((PIMAGE_IMPORT_BY_NAME)(pbNewBase + pThunkFirst->u1.Function))->Name;
                        pThunkFirst->u1.Function = (ULONG_PTR)GetProcAddress((HMODULE)bpDepBase, cpName);

                        if (pThunkFirst->u1.Function == 0)
                        {
                            LDR_LOG("%s: missing import %s.%s", GetOriginalImageName(pbNewBase), cpLibraryName, cpName);
                            dealloc(pbNewBase);
                            return 0;
                        }
                    }
                    // get the next imported function
                    pThunkFirst++;
                    if (pThunkOrig)
                        pThunkOrig++;
                }
            }
            else
            {
                LDR_LOG("%s not found!", cpLibraryName);
                dealloc(pbNewBase);
                return 0;
            }

            // get the next import
            pImport++;
        }
    }

    // STEP 5: process all of our images relocations...

    // check if their are any relocations present
    if (pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
    {
        // calculate the base address delta and perform relocations (even if we load at desired image base)
        ULONG_PTR delta = (ULONG_PTR)(pbNewBase - pNtHdr->OptionalHeader.ImageBase);

        // uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
        auto pReloc = (PIMAGE_BASE_RELOCATION)(pbNewBase +
            pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        // and we iterate through all entries...
        while (pReloc->SizeOfBlock)
        {
            ULONG_PTR relocVA = (ULONG_PTR)(pbNewBase + pReloc->VirtualAddress);
            DWORD entryCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
            PIMAGE_RELOC pRelocBlock = (PIMAGE_RELOC)(pReloc + 1);

            // we iterate through all the entries in the current block...
            while (entryCount--)
            {
                // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
                // we don't use a switch statement to avoid the compiler building a jump table
                // which would not be very position independent!
                if (pRelocBlock->type == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR*)(relocVA + pRelocBlock->offset) += delta;
                else if (pRelocBlock->type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD*)(relocVA + pRelocBlock->offset) += (DWORD)delta;
#ifdef REFLECTIVEDLL_WINARM
                // Note: On ARM, the compiler optimization /O2 seems to introduce an off by one issue, possibly a code gen bug. Using /O1 instead avoids this problem.
                else if( pRelocBlock->type == IMAGE_REL_BASED_ARM_MOV32T )
                {
                    register DWORD dwInstruction;
                    register DWORD dwAddress;
                    register WORD wImm;
                    // get the MOV.T instructions DWORD value (We add 4 to the offset to go past the first MOV.W which handles the low word)
                    dwInstruction = *(DWORD *)( relocVA + pRelocBlock->offset + sizeof(DWORD) );
                    // flip the words to get the instruction as expected
                    dwInstruction = MAKELONG( HIWORD(dwInstruction), LOWORD(dwInstruction) );
                    // sanity chack we are processing a MOV instruction...
                    if( (dwInstruction & ARM_MOV_MASK) == ARM_MOVT )
                    {
                        // pull out the encoded 16bit value (the high portion of the address-to-relocate)
                        wImm  = (WORD)( dwInstruction & 0x000000FF);
                        wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
                        wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
                        wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
                        // apply the relocation to the target address
                        dwAddress = ( (WORD)HIWORD(delta) + wImm ) & 0xFFFF;
                        // now create a new instruction with the same opcode and register param.
                        dwInstruction  = (DWORD)( dwInstruction & ARM_MOV_MASK2 );
                        // patch in the relocated address...
                        dwInstruction |= (DWORD)(dwAddress & 0x00FF);
                        dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
                        dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
                        dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
                        // now flip the instructions words and patch back into the code...
                        *(DWORD *)( relocVA + pRelocBlock->offset + sizeof(DWORD) ) = MAKELONG( HIWORD(dwInstruction), LOWORD(dwInstruction) );
                    }
                }
#endif
                else if (pRelocBlock->type == IMAGE_REL_BASED_HIGH)
                    *(WORD*)(relocVA + pRelocBlock->offset) += HIWORD(delta);
                else if (pRelocBlock->type == IMAGE_REL_BASED_LOW)
                    *(WORD*)(relocVA + pRelocBlock->offset) += LOWORD(delta);

                pRelocBlock++;
            }

            // get the next entry in the relocation directory
            pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
        }
    }

    // Register EH
#if REFLECTIVEDLL_WIN64
    PIMAGE_DATA_DIRECTORY pExceptionDir = &pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (pExceptionDir->Size != 0)
    {
        _api->RtlAddFunctionTable((PRUNTIME_FUNCTION)(pbNewBase + pExceptionDir->VirtualAddress),
                                  pExceptionDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pbNewBase);
    }
#endif

    // STEP 6: call our images entry point

    // We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
    _api->FlushInstructionCache((HANDLE)-1, NULL, 0);

    // call our respective entry point, fudging our hInstance value
    // if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
    // import forwarder modules may not have entry point
    if (pNtHdr->OptionalHeader.AddressOfEntryPoint)
    {
        DLLMAIN pEntryPoint = (DLLMAIN)(pbNewBase + pNtHdr->OptionalHeader.AddressOfEntryPoint);
        pEntryPoint((HINSTANCE)pbNewBase, DLL_PROCESS_ATTACH, lpParameter);
    }

    // For keeping track of all loaded modules and resolving imports from them.
    RegisterLoadedModule((HMODULE)pbNewBase);

    // STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
    return (HMODULE)pbNewBase;
}


DWORD Rva2Offset(DWORD dwRva, PBYTE bpBaseAddress)
{
    WORD wIndex = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;

    pNtHeaders = (PIMAGE_NT_HEADERS)(bpBaseAddress + ((PIMAGE_DOS_HEADER)bpBaseAddress)->e_lfanew);

    pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) +
                                             pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if (dwRva < pSectionHeader[0].PointerToRawData)
        return dwRva;

    for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
    {
        if (dwRva >= pSectionHeader[wIndex].VirtualAddress &&
            dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
        {
            return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
        }
    }

    return 0;
}

DWORD Ldr::GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer)
{
    PBYTE pBase = (PBYTE)lpReflectiveDllBuffer;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(pBase + ((PIMAGE_DOS_HEADER)pBase)->e_lfanew);
    PIMAGE_DATA_DIRECTORY pExportsDir;

    // currently we can only process a PE file which is the same type as the one this function has
    // been compiled as, due to various offset in the PE structures being defined at compile time.
    if (pNtHdr->OptionalHeader.Magic == 0x010B) // PE32
        pExportsDir = &((PIMAGE_NT_HEADERS32)pNtHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    else if (pNtHdr->OptionalHeader.Magic == 0x020B) // PE64
        pExportsDir = &((PIMAGE_NT_HEADERS64)pNtHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    else
        return 0;

    // get the File Offset of the export directory
    PIMAGE_EXPORT_DIRECTORY pExports = (PIMAGE_EXPORT_DIRECTORY)(pBase +
                                                                 Rva2Offset(pExportsDir->VirtualAddress, pBase));

    // get the File Offset for the array of name pointers
    PDWORD dwpNameArray = (PDWORD)(pBase + Rva2Offset(pExports->AddressOfNames, pBase));

    // get the File Offset for the array of name ordinals
    PWORD wpNameOrdinals = (PWORD)(pBase + Rva2Offset(pExports->AddressOfNameOrdinals, pBase));

    // loop through all the exported functions to find the ReflectiveLoader
    for (int i = 0; i < pExports->NumberOfNames; i++)
    {
        char* cpExportedFunctionName = (char*)(pBase + Rva2Offset(*dwpNameArray, pBase));
        if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL)
        {
            // get the File Offset for the array of addresses
            // use the functions name ordinal as an index into the array of name pointers
            PDWORD dwpAddressArray = (PDWORD)(pBase + Rva2Offset(pExports->AddressOfFunctions, pBase) +
                                              (*wpNameOrdinals * sizeof(DWORD)));
            return Rva2Offset(*dwpAddressArray, pBase);
        }
        dwpNameArray++;
        wpNameOrdinals++;
    }

    return 0;
}

// Note: You must compile whatever you are injecting with REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
//       defined in order to use the correct RDI prototypes.
// Note: The hProcess handle must have these access rights: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
//       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// Note: If you are passing in an lpParameter value, if it is a pointer, remember it is for a different address space.
// Note: This function currently cant inject accross architectures, but only to architectures which are the
//       same as the arch this function is compiled as, e.g. x86->x86 and x64->x64 but not x64->x86 or x86->x64.
HANDLE Ldr::LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
    LPVOID lpRemoteLibraryBuffer = NULL;
    LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
    HANDLE hThread = NULL;
    DWORD dwReflectiveLoaderOffset = 0;
    DWORD dwThreadId = 0;
    DWORD dwOldProtect = 0;

#if !__GNUC__
    __try
#endif
    {
        do
        {
            if (!hProcess || !lpBuffer || !dwLength)
                break;

            // check if the library has a ReflectiveLoader...
            dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
            if (!dwReflectiveLoaderOffset)
                break;

            // alloc memory (RW) in the host process for the image...
            lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (!lpRemoteLibraryBuffer)
                break;

            // write the image into the host process...
            if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
                break;

            // change the permissions to (RX) to bypass W^X protections
            if (!VirtualProtectEx(hProcess, lpRemoteLibraryBuffer, dwLength, PAGE_EXECUTE_READ, &dwOldProtect))
                break;

            // add the offset to ReflectiveLoader() to the remote library address...
            lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

            // create a remote thread in the host process to call the ReflectiveLoader!
            hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter, 0, &dwThreadId);

        } while (0);

        if (hThread == 0 && lpRemoteLibraryBuffer)
            VirtualFreeEx(hProcess, lpRemoteLibraryBuffer, dwLength, MEM_RELEASE);
    }
#if !__GNUC__
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        hThread = NULL;
    }
#endif
    return hThread;
}

HMODULE Ldr::LoadLibraryR(LPVOID lpBuffer, DWORD dwLength)
{
    HMODULE hResult = NULL;
    DWORD dwReflectiveLoaderOffset = 0;
    DWORD dwOldProtect1 = 0;
    DWORD dwOldProtect2 = 0;

    if (lpBuffer == NULL || dwLength == 0)
        return NULL;
#if !__GNUC__
    __try
#endif
    {
        // check if the library has a ReflectiveLoader...
        dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
        if (dwReflectiveLoaderOffset == 0)
            return 0;

        auto pReflectiveLoader = (decltype(&ReflectiveLoader))((PBYTE)lpBuffer + dwReflectiveLoaderOffset);

        // we must VirtualProtect the buffer to RWX so we can execute the ReflectiveLoader...
        // this assumes lpBuffer is the base address of the region of pages and dwLength the size of the region
        if (VirtualProtect(lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1))
        {
            hResult = pReflectiveLoader(0);
            VirtualProtect(lpBuffer, dwLength, dwOldProtect1, &dwOldProtect2);
        }
    }
#if !__GNUC__
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        hResult = NULL;
    }
#endif
    return hResult;
}

void* Ldr::GetPEB()
{
#if REFLECTIVEDLL_WIN64
    return (void*)__readgsqword(0x60);
#elif REFLECTIVEDLL_WIN32
    return (void*)__readfsdword(0x30);
#elif REFLECTIVEDLL_WINARM
    return (void*)*(DWORD *)( (BYTE *)_MoveFromCoprocessor( 15, 0, 13, 0, 2 ) + 0x30 );
#endif
}

void Ldr::LoadApi()
{
    ReflectiveApi api{};

    auto pPEB = (_PPEB)GetPEB();
    PPEB_LDR_DATA pLdr = pPEB->pLdr;

    // get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
    // get the first entry of the InMemoryOrder module list
    PLDR_DATA_TABLE_ENTRY pLdrEntry = CONTAINING_RECORD(pLdr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY,
                                                        InMemoryOrderModuleList);

    DWORD dwModulesImported = 0;
    while (pLdrEntry && dwModulesImported < 2)
    {
        DWORD dllNameHash = hashW(&pLdrEntry->BaseDllName);
        auto bpDllBase = (HMODULE)pLdrEntry->DllBase;
        if (dllNameHash == KERNEL32DLL_HASH)
        {
            array_string(name_LoadLibraryA, "LoadLibraryA");
            array_string(name_GetProcAddress, "GetProcAddress");
            array_string(name_VirtualAlloc, "VirtualAlloc");
            array_string(name_VirtualFree, "VirtualFree");
            array_string(name_FlushInstructionCache, "FlushInstructionCache");
            api.LoadLibraryA = (decltype(&::LoadLibraryA))GetProcAddressR(bpDllBase, name_LoadLibraryA);
            api.GetProcAddress = (decltype(&::GetProcAddress))GetProcAddressR(bpDllBase, name_GetProcAddress);
            api.VirtualAlloc = (decltype(&::VirtualAlloc))GetProcAddressR(bpDllBase, name_VirtualAlloc);
            api.VirtualFree = (decltype(&::VirtualFree))GetProcAddressR(bpDllBase, name_VirtualFree);
            api.FlushInstructionCache =
                (decltype(&::FlushInstructionCache))GetProcAddressR(bpDllBase, name_FlushInstructionCache);
            dwModulesImported++;
        }
        else if (dllNameHash == NTDLLDLL_HASH)
        {
#if REFLECTIVEDLL_WIN64
            array_string(name_RtlAddFunctionTable, "RtlAddFunctionTable");
            api.RtlAddFunctionTable = (RTLADDFUNCTIONTABLE)GetProcAddressR(bpDllBase, name_RtlAddFunctionTable);
#endif
            dwModulesImported++;
        }

        // get the next entry
        pLdrEntry = CONTAINING_RECORD(pLdrEntry->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY,
                                      InMemoryOrderModuleList);
    }

    _api = (ReflectiveApi*)api.VirtualAlloc(0, sizeof(api), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    memcpy_i(this->_api, &api, sizeof(api));
}

void Ldr::RegisterLoadedModule(HMODULE hModule)
{
    auto module = alloc<ReflectiveModule>();
    module->hModule = hModule;
    module->cpName = GetOriginalImageName(hModule);
    InsertTailList(&_reflectiveModules, module);
}

template<typename T>
T* Ldr::alloc(DWORD protect)
{
    return (T*)alloc(sizeof(T), protect);
}

void* Ldr::alloc(size_t size, DWORD protect)
{
    return _api->VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT, protect);
}

template<typename T>
bool Ldr::dealloc(T* object)
{
    return _api->VirtualFree(object, 0, MEM_RELEASE) != FALSE;
}

HMODULE Ldr::LoadLibrary(const char* cpName)
{
    // Return already loaded reflective module handle if any.
    HMODULE hModule = GetModuleHandleR(cpName);

    // Load reflective module from cache if any.
    if (!hModule)
    {
        FOREACH_LIST_ENTRY(CachedModule, m, _cachedModules)
        {
            if (stricmp_i(m->module, cpName) == 0)
            {
                hModule = MapImageAndExecute(m->pImage, 0);
                if (hModule)
                {
                    dealloc(m->pImage);
                    RemoveEntryList(m);
                    dealloc(m);
                }
                break;
            }
        }
    }

    // If no reflective modules are present let the OS load the file.
    if (!hModule)
        hModule = _api->LoadLibraryA(cpName);

    return hModule;
}

FARPROC Ldr::GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    FARPROC result = 0;
    if (IsReflectiveModule(hModule))
        result = GetProcAddressR(hModule, lpProcName);
    else
        result = _api->GetProcAddress((HMODULE)hModule, lpProcName);

    if (!result)
    {
        const char* cpModuleName = GetOriginalImageName(hModule);
        FOREACH_LIST_ENTRY(ImportMapping, m, _importAlternatives)
        {
            if (stricmp_i(m->module, cpModuleName, sizeof(m->module)) == 0 &&
                strcmp_i(m->proc, lpProcName, sizeof(m->proc)) == 0)
            {
                result = m->pOverride;
                break;
            }
        }
    }

    return result;
}

void Ldr::SetImportAlternative(const char* cpModuleName, const char* cpProcName, FARPROC pNewProc)
{
    auto* import = alloc<ImportMapping>();
    import->pOverride = pNewProc;
    strcpy_i(import->module, cpModuleName, sizeof(import->module));
    strcpy_i(import->proc, cpProcName, sizeof(import->proc));
    InsertTailList(&_importAlternatives, import);
}

HMODULE Ldr::GetModuleHandleR(const char* cpName)
{
    FOREACH_LIST_ENTRY(ReflectiveModule, m, _reflectiveModules)
    {
        // In case modules are queried using full name.
        if (stricmp_i(m->cpName, cpName) == 0)
            return m->hModule;
    }
    return 0;
}

bool Ldr::IsReflectiveModule(HMODULE hModule)
{
    FOREACH_LIST_ENTRY(ReflectiveModule, m, _reflectiveModules)
    {
        if (m->hModule == hModule)
            return true;
    }
    return false;
}

void Ldr::SetCachedModule(const char* cpModuleName, const void* pImage, size_t nImageLength)
{
    auto m = alloc<CachedModule>();
    strcpy_i(m->module, cpModuleName, sizeof(m->module));
    void* pImageCopy = alloc(nImageLength);
    memcpy_i(pImageCopy, pImage, nImageLength);
    m->pImage = pImageCopy;
    m->nImageLength = nImageLength;
    InsertTailList(&_cachedModules, m);
}

}


extern "C"
{

// This is our position independent reflective DLL loader/injector
__declspec(dllexport) HMODULE WINAPI ReflectiveLoader(LPVOID lpParameter)
{
    // the initial location of this image in memory
    ULONG_PTR uiLibraryAddress;

    // variables for loading this image
    ULONG_PTR uiHeaderValue;

    // STEP 0: calculate our images current base address
    // we will start searching backwards from our callers return address.
    uiLibraryAddress = Reflective::caller();

    // loop through memory backwards searching for our images base address
    // we dont need SEH style search as we shouldnt generate any access violations with this
    for (;;)
    {
        if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
        {
            uiHeaderValue = (ULONG_PTR)((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
            // some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
            // we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
            if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
            {
                uiHeaderValue += uiLibraryAddress;
                // break if we have found a valid MZ/PE header
                if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE)
                    break;
            }
        }
        uiLibraryAddress--;
    }
    Reflective::Ldr ldr;
    return ldr.MapImageAndExecute((LPVOID)uiLibraryAddress, lpParameter);
}

}
