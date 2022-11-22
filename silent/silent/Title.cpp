#include "Title.h"
#include "stdafx.h"
BOOL dashLoaded = FALSE;
VOID InitializeTitleHooks(PLDR_DATA_TABLE_ENTRY Handle) {
	PatchModuleImport(Handle, MODULE_KERNEL, 0x198, (DWORD)XexLoadExecutableHook);
	PatchModuleImport(Handle, MODULE_KERNEL, 0x199, (DWORD)XexLoadImageHook);
	XEX_EXECUTION_ID* pExecutionId = (XEX_EXECUTION_ID*)RtlImageXexHeaderField(Handle->XexHeaderBase, 0x00040006);
	if (pExecutionId == 0) return;
	if (wcscmp(Handle->BaseDllName.Buffer, L"dash.xex") == 0) {
		dashLoaded = TRUE;
	}
}

