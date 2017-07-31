//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// Copyright (c) 2017, Rokas Kupstys
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
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
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
#include "ReflectiveDLL_p.h"


#pragma intrinsic( _ReturnAddress )
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


int _loaded_reflective_dlls_count = 0;
HMODULE _loaded_reflective_dlls[512];

// Note 1: If you want to have your own DllMain, define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN,
//         otherwise the DllMain at the end of this file will be used.

// We implement a minimal GetProcAddress to avoid using the native kernel32!GetProcAddress which
// wont be able to resolve exported addresses in reflectivly loaded librarys.
FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName)
{
    PBYTE bpBase = hModule;
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
            fpResult = (FARPROC)(bpBase +
                                 dwpAddressArray[(IMAGE_ORDINAL((size_t)lpProcName) - pExportDirectory->Base)]);
        }
        else
        {
            // import by name...
            DWORD dwCounter = pExportDirectory->NumberOfNames;
            while (dwCounter--)
            {
                char* cpExportedFunctionName = (char*)(bpBase + *dwpNameArray);

                // test if we have a match...
                if (strcmp(cpExportedFunctionName, lpProcName) == 0)
                {
                    // use the functions name ordinal as an index into the array of name pointers
                    fpResult = (FARPROC)(bpBase + dwpAddressArray[*wpNameOrdinals]);
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
ULONG_PTR WINAPI p_ReflectiveLoader(LPVOID lpImage, LPVOID lpParameter, int force_pic)
{
    // the functions we need
    LOADLIBRARYA pLoadLibraryA = NULL;
    GETPROCADDRESS pGetProcAddress = NULL;
    VIRTUALALLOC pVirtualAlloc = NULL;
    NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;
#if WIN64
    RTLADDFUNCTIONTABLE pRtlAddFunctionTable = NULL;
#endif

    // STEP 1: process the kernels exports for the functions our loader needs...

#if WIN64
    _PPEB pPEB = (_PPEB)__readgsqword(0x60);
#elif WIN32
    _PPEB pPEB = (_PPEB)__readfsdword( 0x30 );
#elif WINARM
    _PPEB pPEB = (_PPEB)*(DWORD *)( (BYTE *)_MoveFromCoprocessor( 15, 0, 13, 0, 2 ) + 0x30 );
#endif
    PPEB_LDR_DATA pLdr = pPEB->pLdr;

    // get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx

    // get the first entry of the InMemoryOrder module list
    PLDR_DATA_TABLE_ENTRY pLdrEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pLdr->InMemoryOrderModuleList.Flink -
                                                              offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList));
    while (pLdrEntry)
    {
        DWORD dllNameHash = hashW(&pLdrEntry->BaseDllName);

        PBYTE bpDllBase = (PBYTE)pLdrEntry->DllBase;
        PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)bpDllBase;
        PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(bpDllBase + pDosHdr->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(bpDllBase +
            pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        PDWORD nameArray = (PDWORD)(bpDllBase + exportDir->AddressOfNames);
        PWORD nameOrdinals = (PWORD)(bpDllBase + exportDir->AddressOfNameOrdinals);

        if (dllNameHash == KERNEL32DLL_HASH)
        {
            while (!pLoadLibraryA || !pGetProcAddress || !pVirtualAlloc)
            {
                // compute the hash values for this function name
                DWORD hashValue = hashA((char*)(bpDllBase + *nameArray));
                // get the VA for the array of addresses
                PDWORD addressOfFunctions = (PDWORD)(bpDllBase + exportDir->AddressOfFunctions);

                if (hashValue == LOADLIBRARYA_HASH)
                    pLoadLibraryA = (LOADLIBRARYA)(bpDllBase + addressOfFunctions[*nameOrdinals]);
                else if (hashValue == GETPROCADDRESS_HASH)
                    pGetProcAddress = (GETPROCADDRESS)(bpDllBase + addressOfFunctions[*nameOrdinals]);
                else if (hashValue == VIRTUALALLOC_HASH)
                    pVirtualAlloc = (VIRTUALALLOC)(bpDllBase + addressOfFunctions[*nameOrdinals]);

                nameArray++;
                nameOrdinals++;
            }
        }
        else if (dllNameHash == NTDLLDLL_HASH)
        {
#if WIN64
            while (!pNtFlushInstructionCache || !pRtlAddFunctionTable)
#else
            while (!pNtFlushInstructionCache)
#endif
            {
                // compute the hash values for this function name
                DWORD hashValue = hashA((char*)(bpDllBase + *nameArray));
                // get the VA for the array of addresses
                PDWORD addressOfFunctions = (PDWORD)(bpDllBase + exportDir->AddressOfFunctions);

                if (hashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
                    pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(bpDllBase + addressOfFunctions[*nameOrdinals]);
#if WIN64
                else if (hashValue == RTLADDFUNCTIONTABLE_HASH)
                    pRtlAddFunctionTable = (RTLADDFUNCTIONTABLE)(bpDllBase + addressOfFunctions[*nameOrdinals]);
#endif

                nameArray++;
                nameOrdinals++;
            }
        }

        // we stop searching when we have found everything we need.
        if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache)
        {
#if WIN64
            if (pRtlAddFunctionTable)
#endif
                break;
        }

        // get the next entry
        pLdrEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pLdrEntry->InMemoryOrderModuleList.Flink -
                                            offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList));
    }

    // STEP 2: load our image into a new permanent location in memory...

    // get the VA of the NT Header for the PE to be loaded
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(lpImage + ((PIMAGE_DOS_HEADER)lpImage)->e_lfanew);

    // allocate all the memory for the DLL to be loaded into. we can load at any address because we will
    // relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
    PBYTE newBase = (PBYTE)pVirtualAlloc(NULL, pNtHdr->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT,
                                         PAGE_EXECUTE_READWRITE);

    // we must now copy over the headers
    memcpy_i(newBase, lpImage, pNtHdr->OptionalHeader.SizeOfHeaders);

    // STEP 3: load in all of our sections...
    PIMAGE_SECTION_HEADER pSection = ((PIMAGE_SECTION_HEADER)((PBYTE)&pNtHdr->OptionalHeader +
                                                              pNtHdr->FileHeader.SizeOfOptionalHeader));
    for (WORD i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++, pSection++)
    {
        memcpy_i(newBase + pSection->VirtualAddress, (PBYTE)lpImage + pSection->PointerToRawData,
                 pSection->SizeOfRawData);
    }
    // STEP 4: process our images import table...
    // we assume their is an import table to process
    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(newBase +
        pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // iterate through all imports
    while (pImport->Name)
    {
        // use LoadLibraryA to load the imported module into memory
        PBYTE bpDepBase = (PBYTE)pLoadLibraryA((LPCSTR)(newBase + pImport->Name));

        BOOL bUseReflectiveGetProcAddress = 0;
        if (bpDepBase == 0)
        {
            if (force_pic == 0)
            {
                for (int i = 0; i < _loaded_reflective_dlls_count; i++)
                {
                    // Get original image name.
                    PBYTE refDepBase = (PBYTE)_loaded_reflective_dlls[i];
                    PIMAGE_DOS_HEADER pRefDos = (PIMAGE_DOS_HEADER)refDepBase;
                    PIMAGE_NT_HEADERS pRefNt = (PIMAGE_NT_HEADERS)(refDepBase + pRefDos->e_lfanew);
                    PIMAGE_EXPORT_DIRECTORY pRefExp = (PIMAGE_EXPORT_DIRECTORY)(refDepBase +
                        pRefNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                    const char* dllName = (const char*)(refDepBase + pRefExp->Name);

                    if (strcmp_i(dllName, (const char*)(newBase + pImport->Name)) == 0)
                    {
                        bpDepBase = (PBYTE)refDepBase;
                        bUseReflectiveGetProcAddress = 1;
                        break;
                    }
                }
            }
            else
            {
                // Failed to load required imports.
                return 0;
            }
        }

        PIMAGE_THUNK_DATA pThunkOrig = (PIMAGE_THUNK_DATA)(newBase + pImport->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pThunkFirst = (PIMAGE_THUNK_DATA)(newBase + pImport->FirstThunk);
        PIMAGE_NT_HEADERS pNtHdrDep = (PIMAGE_NT_HEADERS)(bpDepBase + ((PIMAGE_DOS_HEADER)bpDepBase)->e_lfanew);

        // iterate through all imported functions, importing by ordinal if no name present
        while (pThunkFirst->u1.Function)
        {
            if (pThunkOrig && (pThunkOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG))
            {
                PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(bpDepBase +
                    pNtHdrDep->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                PDWORD addressArray = (PDWORD)(bpDepBase + exportDir->AddressOfFunctions);
                pThunkFirst->u1.Function = (UINT_PTR)(bpDepBase +
                                                      addressArray[IMAGE_ORDINAL(pThunkOrig->u1.Ordinal) -
                                                                   exportDir->Base]);
            }
            else
            {
                LPCSTR cpName = (LPCSTR)((PIMAGE_IMPORT_BY_NAME)(newBase + pThunkFirst->u1.Function))->Name;
                if (bUseReflectiveGetProcAddress)
                {
                    // use GetProcAddressR and patch in the address for this imported function
                    pThunkFirst->u1.Function = (ULONG_PTR)GetProcAddressR((HMODULE)bpDepBase, cpName);
                }
                else
                {
                    // use GetProcAddress and patch in the address for this imported function
                    pThunkFirst->u1.Function = (ULONG_PTR)pGetProcAddress((HMODULE)bpDepBase, cpName);
                }
            }
            // get the next imported function
            pThunkFirst++;
            if (pThunkOrig)
                pThunkOrig++;
        }

        // get the next import
        pImport++;
    }

    // STEP 5: process all of our images relocations...

    // calculate the base address delta and perform relocations (even if we load at desired image base)
    ULONG_PTR delta = (ULONG_PTR)(newBase - pNtHdr->OptionalHeader.ImageBase);

    // check if their are any relocations present
    if (pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
    {
        // uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(newBase +
            pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        // and we iterate through all entries...
        while (pReloc->SizeOfBlock)
        {
            ULONG_PTR relocVA = (ULONG_PTR)(newBase + pReloc->VirtualAddress);
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
#ifdef WINARM
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
#if WIN64
    PIMAGE_DATA_DIRECTORY pExceptionDir = &pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (pExceptionDir->Size != 0)
    {
        pRtlAddFunctionTable((PRUNTIME_FUNCTION)(newBase + pExceptionDir->VirtualAddress),
                             pExceptionDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)newBase);
    }
#endif

    // STEP 6: call our images entry point

    // We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
    pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

    // Save dll handle so later modules can use it for getting imports.
    if (force_pic == 0)
        _loaded_reflective_dlls[_loaded_reflective_dlls_count++] = (HMODULE)newBase;

    // call our respective entry point, fudging our hInstance value
    // if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
    ((DLLMAIN)newBase + pNtHdr->OptionalHeader.AddressOfEntryPoint)((HINSTANCE)newBase, DLL_PROCESS_ATTACH, lpParameter);

    // STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
    return (ULONG_PTR)newBase;
}

// This is our position independent reflective DLL loader/injector
__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
{
    // the initial location of this image in memory
    ULONG_PTR uiLibraryAddress;

    // variables for loading this image
    ULONG_PTR uiHeaderValue;

    // STEP 0: calculate our images current base address
    // we will start searching backwards from our callers return address.
    uiLibraryAddress = caller();

    // loop through memory backwards searching for our images base address
    // we dont need SEH style search as we shouldnt generate any access violations with this
    while (TRUE)
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

    return p_ReflectiveLoader((LPVOID)uiLibraryAddress, lpParameter, 1);
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

DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer)
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

// Loads a DLL image from memory via its exported ReflectiveLoader function
HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength)
{
    HMODULE hResult = NULL;
    DWORD dwReflectiveLoaderOffset = 0;
    DWORD dwOldProtect1 = 0;
    DWORD dwOldProtect2 = 0;
    REFLECTIVELOADER pReflectiveLoader = NULL;
    DLLMAIN pDllMain = NULL;

    if (lpBuffer == NULL || dwLength == 0)
        return NULL;
#if !__GNUC__
    __try
#endif
    {
        // check if the library has a ReflectiveLoader...
        dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
        if (dwReflectiveLoaderOffset != 0)
            pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);

        // we must VirtualProtect the buffer to RWX so we can execute the ReflectiveLoader...
        // this assumes lpBuffer is the base address of the region of pages and dwLength the size of the region
        if (VirtualProtect(lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1))
        {
            if (pReflectiveLoader)
            {
                pDllMain = (DLLMAIN)pReflectiveLoader();
                if (pDllMain != NULL)
                {
                    // call the loaded librarys DllMain to get its HMODULE
                    if (!pDllMain(NULL, DLL_QUERY_HMODULE, &hResult))
                        hResult = NULL;
                }
            }
            else
                hResult = (HMODULE)p_ReflectiveLoader(lpBuffer, 0, 0);
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

// Loads a PE image from memory into the address space of a host process via the image's exported ReflectiveLoader function
// Note: You must compile whatever you are injecting with REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
//       defined in order to use the correct RDI prototypes.
// Note: The hProcess handle must have these access rights: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
//       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// Note: If you are passing in an lpParameter value, if it is a pointer, remember it is for a different address space.
// Note: This function currently cant inject accross architectures, but only to architectures which are the
//       same as the arch this function is compiled as, e.g. x86->x86 and x64->x64 but not x64->x86 or x86->x64.
HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
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

    }
#if !__GNUC__
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        hThread = NULL;
    }
#endif
    return hThread;
}
