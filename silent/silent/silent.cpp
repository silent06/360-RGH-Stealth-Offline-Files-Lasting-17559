#include "stdafx.h"
HANDLE dllHandle = NULL;
BOOL FindPaths() {
	BOOL RunningFromUSB = FALSE;
	if ((XboxHardwareInfo->Flags & 0x20) == 0x20) {
		CreateSymbolicLink("HDD:\\", "\\Device\\Harddisk0\\Partition1", TRUE);
	}
	else {
		CreateSymbolicLink("USB:\\", "\\Device\\Mass0", TRUE);
		RunningFromUSB = TRUE;
	}
	PATH_KV = (RunningFromUSB ? "USB:\\kv.bin" : "HDD:\\kv.bin");
	PATH_CPU_BIN = (RunningFromUSB ? "USB:\\cpukey.bin" : "HDD:\\cpukey.bin");
	PATH_XEX = (RunningFromUSB ? "USB:\\silent.xex" : "HDD:\\silent.xex");
	return TRUE;
}
BOOL Initialize() {
	if (!FindPaths())  return E_FAIL; 
	if (!InitializeHvxPeekPoke()) return FALSE;
	if (!BootloaderHV()) return FALSE;
	if (!SetKeyVault()) return FALSE;
	if (!InitializeSystemHooks()) return FALSE;
	return TRUE;
}
BOOL APIENTRY DllMain(HANDLE Handle, DWORD Reason, PVOID Reserved) {
	dllHandle = Handle;
	if (Reason == DLL_PROCESS_ATTACH) {
		if (TrayOpen()) return 0xC0000001;
		else if (!Initialize()) HalReturnToFirmware(HalResetSMCRoutine);
	} return TRUE;
}