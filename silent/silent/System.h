#include "stdafx.h"
extern NTSTATUS XexLoadExecutableHook(PCHAR Name, PHANDLE Handle, DWORD TypeFlags, DWORD Version);
extern NTSTATUS XexLoadImageHook(CONST PCHAR Name, DWORD TypeFlags, DWORD Version, PHANDLE Handle);
extern BOOL InitializeSystemHooks();
extern DWORD XeKeysExecuteHook(BYTE* pBuffer, DWORD respSize, BYTE* HvSalt, PVOID r6, PVOID r7, PVOID r8);
extern void* RtlImageXexHeaderFieldHook(void* headerBase, DWORD imageKey);
static PVOID(__cdecl *mmGetPhysicalAddress)(PVOID ptr) = (PVOID(*)(PVOID))0x80080048;
static DWORD(__cdecl *xeKeysExecute)(PVOID pvPhyBuffer, DWORD len, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4) = (DWORD(*)(PVOID, DWORD, PVOID, PVOID, PVOID, PVOID))0x80109FF8;