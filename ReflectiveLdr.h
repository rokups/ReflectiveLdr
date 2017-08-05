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
#   define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace Reflective
{

struct ReflectiveApi;

struct ReflectiveModule : LIST_ENTRY
{
    /// Pointer to original module name in module EAT.
    const char* cpName;
    /// Base address at which module was loaded.
    HMODULE hModule;
};

struct ImportMapping : LIST_ENTRY
{
    /// Name of DLL whose export is to be overriden.
    char module[128];
    /// Name of procedure that will be overriden.
    char proc[64];
    /// Pointer to another procedure that will replace original one.
    FARPROC pOverride;
};

struct CachedModule : LIST_ENTRY
{
    /// Name of DLL that will be cached.
    char module[128];
    /// Pointer to memory range which contains module PE image.
    void* pImage;
    /// Pength of memory pointed to by `pImage`.
    size_t nImageLength;
};

class Ldr
{
public:
    Ldr();
    ~Ldr();

    /// Loads exported function address from a mapped module. Works with reflective modules. Handles API overriding too.
    FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
    /// Returns a handle of loaded memory module.
    HMODULE GetModuleHandleR(const char* cpName);
    /// Returns true if handle points to module loaded by reflective loader.
    bool IsReflectiveModule(HMODULE hModule);
    /// Replacement for LoadLibraryA. Returns HMODULE for reflectively loaded modules as well.
    HMODULE LoadLibrary(const char* cpName);
    /// Actual loader that maps image to memory and executes main function.
    HMODULE MapImageAndExecute(LPCVOID lpImage, LPVOID lpParameter);
    /// Set import alternative. New pNewProc will be returned when original import is missing.
    void SetImportAlternative(const char* cpModuleName, const char* cpProcName, FARPROC pNewProc);
    /// Insert a module to a cache. Cached modules will be reflectively-loaded when resolving imports.
    void SetCachedModule(const char* cpModuleName, const void* pImage, size_t nImageLength);
    /// Returns pointer to PEB of current process.
    void* GetPEB();
    /// Loads exported function address from a mapped module.
    FARPROC GetProcAddressR(HMODULE hModule, LPCSTR lpProcName);
    /// Returns original image name taken from EAT, null pointer if image does not have EAT.
    const char* GetOriginalImageName(PVOID bpBase);
    /// Returns raw offset of exported reflective loader in specified unmapped PE image.
    DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer);

    /// Loads a PE image from memory into the address space of a host process via the image's exported ReflectiveLoader 
    /// function. Position-dependent!
    HANDLE LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter);
    /// Loads a DLL image from memory via its exported ReflectiveLoader function. Position-dependent!
    HMODULE LoadLibraryR(LPVOID lpBuffer, DWORD dwLength);

protected:
    ReflectiveApi* _api;
    LIST_ENTRY _reflectiveModules;
    LIST_ENTRY _importAlternatives;
    LIST_ENTRY _cachedModules;

    void LoadApi();
    void RegisterLoadedModule(HMODULE hModule);

    template<typename T>
    T* alloc(DWORD protect = PAGE_READWRITE);
    void* alloc(size_t size, DWORD protect = PAGE_READWRITE);
    template<typename T>
    bool dealloc(T* object);
};

}

extern "C"
{
__declspec(dllexport) HMODULE WINAPI ReflectiveLoader(LPVOID lpParameter);
}

/// Macro which creates reflective loader export by referencing reflective loader.
/// Put it at the top scope of your main application.
#define EXPORT_REFLECTIVE_LOADER const static volatile auto ___ref_ReflectiveLoader = &ReflectiveLoader;
