#include "stdafx.h"
	BOOL pfShow = (BOOL)0xDEADBEEF; BOOL pfShowMovie;
	BOOL pfPlaySound; BOOL pfShowIPTV;

	FARPROC ResolveFunction(CHAR* ModuleName, DWORD Ordinal) 
{
	HMODULE mHandle = GetModuleHandle(ModuleName);
	return (mHandle == NULL) ? NULL : GetProcAddress(mHandle, (LPCSTR)Ordinal);
}
	VOID toggleNotify(BOOL on) {
		if ((int)pfShow == 0xDEADBEEF)
			XNotifyUIGetOptions(&pfShow, &pfShowMovie, &pfPlaySound, &pfShowIPTV);
		if (!on) {
			XNotifyUISetOptions(pfShow, pfShowMovie, pfPlaySound, pfShowIPTV);
		}
		else {
			XNotifyUISetOptions(true, true, true, true);
		} Sleep(500);
	}

	VOID XNotifyDoQueueUI(PWCHAR pwszStringParam) {
		toggleNotify(true);
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, pwszStringParam, NULL);
		toggleNotify(false);
	}
	VOID NotifyPopup(PWCHAR myPWCHAR) {
		if (KeGetCurrentProcessType() != PROC_USER) {
			HANDLE th = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)XNotifyDoQueueUI, (LPVOID)myPWCHAR, CREATE_SUSPENDED, NULL);
			if (th == NULL) return; ResumeThread(th);
		}
		else XNotifyDoQueueUI(myPWCHAR);
	}