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
#pragma once


#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>


#if _M_X64 || __x86_64__
#	define WIN64 1
#elif _M_IX86 || __i386__
#	define WIN32 1
#elif _M_ARM || __aarch64__
#	define WINARM
#endif

typedef ULONG_PTR (WINAPI* REFLECTIVELOADER)(VOID);
typedef BOOL (WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
typedef HMODULE (WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC (WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID (WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD (NTAPI* NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);
#if WIN64
typedef BOOLEAN(NTAPI* RTLADDFUNCTIONTABLE)(PRUNTIME_FUNCTION, DWORD, DWORD64);
#endif

#define DLL_QUERY_HMODULE               6
#define KERNEL32DLL_HASH                0x6A4ABC5B
#define NTDLLDLL_HASH                   0x3CFA685D
#define LOADLIBRARYA_HASH               0xEC0E4E8E
#define GETPROCADDRESS_HASH             0x7C0DFCAA
#define VIRTUALALLOC_HASH               0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH    0x534C0AB8
#define RTLADDFUNCTIONTABLE_HASH        0x22FC1661

#define IMAGE_REL_BASED_ARM_MOV32A      5
#define IMAGE_REL_BASED_ARM_MOV32T      7

#define ARM_MOV_MASK                    (DWORD)(0xFBF08000)
#define ARM_MOV_MASK2                   (DWORD)(0xFBF08F00)
#define ARM_MOVW                        0xF2400000
#define ARM_MOVT                        0xF2C00000

#define HASH_KEY                        13

#pragma intrinsic( _rotr )

__forceinline DWORD ror(DWORD d)
{
    return _rotr(d, HASH_KEY);
}

__forceinline char chrtoupper_i(char c)
{
    if (c >= 'a' && c <= 'z')
        c = (char)(c - ('a' - 'A'));
    return c;
}

__forceinline int strcmp_i(const char* a, const char* b)
{
    char ca, cb;
    for (;;)
    {
        ca = chrtoupper_i(*a);
        cb = chrtoupper_i(*b);

        if (ca != cb)
            return ca - cb;

        if (ca == 0)
            return 0;

        a++;
        b++;
    }
}

typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

__forceinline DWORD hashA(char* c)
{
    register DWORD h = 0;
    do
    {
        h = ror(h);
        h += *c;
    } while (*++c);

    return h;
}

__forceinline DWORD hashW(PUNICODE_STR string)
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

__forceinline void memcpy_i(void* dest, void* src, DWORD len)
{
    while (len--)
        *(BYTE*)dest++ = *(BYTE*)src++;
}

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
//__declspec( align(8) ) 
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// WinDbg> dt -v ntdll!_PEB_LDR_DATA
typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

// struct _PEB is defined in Winternl.h but it is incomplete
// WinDbg> dt -v ntdll!_PEB
typedef struct __PEB // 65 elements, 0x210 bytes
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

typedef struct
{
    WORD offset:12;
    WORD type:4;
} IMAGE_RELOC, * PIMAGE_RELOC;
