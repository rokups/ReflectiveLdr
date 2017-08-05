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
#pragma once


#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>


#if _M_X64 || __x86_64__
#	define REFLECTIVEDLL_WIN64 1
#elif _M_IX86 || __i386__
#	define REFLECTIVEDLL_WIN32 1
#elif _M_ARM || __aarch64__
#	define REFLECTIVEDLL_WINARM
#endif


#define DLL_QUERY_HMODULE               6
#define KERNEL32DLL_HASH                0x6A4ABC5B
#define NTDLLDLL_HASH                   0x3CFA685D

#define IMAGE_REL_BASED_ARM_MOV32A      5
#define IMAGE_REL_BASED_ARM_MOV32T      7

#define ARM_MOV_MASK                    (DWORD)(0xFBF08000)
#define ARM_MOV_MASK2                   (DWORD)(0xFBF08F00)
#define ARM_MOVW                        0xF2400000
#define ARM_MOVT                        0xF2C00000

#define HASH_KEY                        13

#define array_string(name, str) char name[sizeof(str)] = str;
#pragma intrinsic( _rotr )


typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

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


#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address,type,field) ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))
#endif

#ifndef InitializeListHead
#define InitializeListHead(ListHead) ((ListHead)->Flink = (ListHead)->Blink = (ListHead))
#define IsListEmpty(ListHead) ((ListHead)->Flink==(ListHead))
#define RemoveHeadList(ListHead) (ListHead)->Flink; {RemoveEntryList((ListHead)->Flink)}
#define RemoveTailList(ListHead) (ListHead)->Blink; {RemoveEntryList((ListHead)->Blink)}
#define RemoveEntryList(Entry) { PLIST_ENTRY _EX_Blink; PLIST_ENTRY _EX_Flink; _EX_Flink = (Entry)->Flink; _EX_Blink = (Entry)->Blink; _EX_Blink->Flink = _EX_Flink; _EX_Flink->Blink = _EX_Blink; }
#define InsertTailList(ListHead,Entry) { PLIST_ENTRY _EX_Blink; PLIST_ENTRY _EX_ListHead; _EX_ListHead = (ListHead); _EX_Blink = _EX_ListHead->Blink; (Entry)->Flink = _EX_ListHead; (Entry)->Blink = _EX_Blink; _EX_Blink->Flink = (Entry); _EX_ListHead->Blink = (Entry); }
#define InsertHeadList(ListHead,Entry) { PLIST_ENTRY _EX_Flink; PLIST_ENTRY _EX_ListHead; _EX_ListHead = (ListHead); _EX_Flink = _EX_ListHead->Flink; (Entry)->Flink = _EX_Flink; (Entry)->Blink = _EX_ListHead; _EX_Flink->Blink = (Entry); _EX_ListHead->Flink = (Entry); }
#endif

#define FOREACH_LIST_ENTRY(type, var, list) \
    for (type* var = (type*)list.Flink; var != &list; var = (type*)var->Flink)

namespace Reflective
{


typedef BOOL (WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
#if REFLECTIVEDLL_WIN64
typedef BOOLEAN(NTAPI* RTLADDFUNCTIONTABLE)(PRUNTIME_FUNCTION, DWORD, DWORD64);
#endif

__forceinline DWORD ror(DWORD d)
{
    return _rotr(d, HASH_KEY);
}

char chrtoupper_i(char c);
void toupper_i(char* str);
int stricmp_i(const char* a, const char* b, size_t n = 0);
int strcmp_i(const char* a, const char* b, size_t n = 0);
DWORD hashW(PUNICODE_STR string);
void memcpy_i(void* dest, const void* src, size_t len);
char* strcpy_i(char* dest, const char* src, size_t n = 0);
void memset_i(void* dest, BYTE b, size_t len);
size_t strlen_i(const char* str);

struct ReflectiveApi
{
    decltype(&::LoadLibraryA) LoadLibraryA;
    decltype(&::GetProcAddress) GetProcAddress;
    decltype(&::VirtualAlloc) VirtualAlloc;
    decltype(&::VirtualFree) VirtualFree;
    decltype(&::FlushInstructionCache) FlushInstructionCache;
#if WIN64
    decltype(&::RtlAddFunctionTable) RtlAddFunctionTable;
#endif
};

}
