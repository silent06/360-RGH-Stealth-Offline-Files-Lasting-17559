#include "stdafx.h"
#include "HV.h"
XEX_EXECUTION_ID SpoofedExecutionId;
detour<VOID> NetDll_XnpLogonSetChallengeResponseOriginal;

// title header

unsigned char dashExid[24] = {
	0x00, 0x00, 0x00, 0x00, 0x20, 0x44, 0x97, 0x00, 0x20, 0x44, 0x97, 0x00,
	0xFF, 0xFE, 0x07, 0xD1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// xexHash

unsigned char xam_da[88] = {
	0x00, 0x00, 0x2D, 0x94, 0x53, 0xD5, 0xD4, 0x39, 0xC7, 0xB0, 0x76, 0x38,
	0x1B, 0x44, 0x86, 0x1E, 0xEB, 0x45, 0x9D, 0x36, 0xCF, 0x47, 0x59, 0xC1,
	0x81, 0xA7, 0x3D, 0x04, 0x81, 0x5F, 0x0B, 0x34, 0x81, 0xA7, 0x3D, 0x14,
	0x81, 0x5F, 0x0B, 0x38, 0x81, 0xA7, 0x3D, 0x24, 0x78, 0x1E, 0x02, 0x60,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
	0x80, 0x00, 0x40, 0x04
};

unsigned char kernel_da[88] = {
	0x00, 0x00, 0x00, 0x20, 0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89,
	0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76, 0xC3, 0xD2, 0xE1, 0xF0,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x45, 0x58, 0x32,
	0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00,
	0x80, 0x04, 0x0B, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x6D, 0xC0
};

unsigned char dash_da[88] = {
	0x00, 0x00, 0x4D, 0xEC, 0xC6, 0x2E, 0xC0, 0xF1, 0x9D, 0x93, 0x96, 0xB1,
	0xF1, 0xE9, 0x0A, 0x29, 0x92, 0x2F, 0xBD, 0x4C, 0xCD, 0xB4, 0x44, 0xEF,
	0x92, 0x00, 0x10, 0xC4, 0x92, 0x00, 0x10, 0xC8, 0x92, 0x93, 0xA4, 0x4C,
	0x92, 0x00, 0x10, 0xCC, 0x92, 0x93, 0xA4, 0x3C, 0x92, 0x00, 0x10, 0xD0,
	0x92, 0x93, 0xA4, 0x2C, 0x92, 0x00, 0x10, 0xD4, 0x92, 0x93, 0xA4, 0x1C,
	0x92, 0x00, 0x10, 0xD8, 0x92, 0x93, 0xC1, 0x9C, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x20
};

DWORD HVSF() {
	DWORD HV_STATUS_FLAG = 0x023289D3;
	HV_STATUS_FLAG = (Crl == 1) ? (HV_STATUS_FLAG | 0x10000) : HV_STATUS_FLAG;
	HV_STATUS_FLAG = (Fcrt == 1) ? (HV_STATUS_FLAG | 0x1000000) : HV_STATUS_FLAG;
	return HV_STATUS_FLAG;
}

void* RtlImageXexHeaderFieldHook(void* headerBase, DWORD imageKey) {
	void* Result = RtlImageXexHeaderField(headerBase, imageKey);
	if (imageKey == 0x40006 && Result) {
		switch (reinterpret_cast<XEX_EXECUTION_ID*>(Result)->TitleID) {
		case 0xC0DE9999: // XeXMenu
		case 0xFFFF0055: // XeXMenu [1]
		case 0xFFFF011D: // Dashlaunch
		case 0xFFFE07FF: // XShellXDK
		case 0xF5D20000: // Freestyle Dash
		case 0x00000166: // Aurora
		case 0x00000189: // Simple 360 NandFlasher
		case 0x00000188: // Flash 360
		case 0x00000176: // XM360
		case 0x00000167: // Freestyle Dash 3
		case 0x00000177: // NXE2GOD
		case 0x00000170: // XeXMenu 2.0
		case 0xFFFEFF43: // XellLaunch [GOD]
		case 0xFEEDC0DE: // XYZ Project
		//case 0x58480880: // IE Homebrew
		case 0x00000001: // FX Menu
		case 0x00000171: // FCEUX
		case 0xFFED0707: // SNES 360
		case 0x1CED2911: // PCSXR
		case 0xFFED7300: // FCE 360
		case 0x00FBAFBA: // DSON 360
		case 0x000003D0: // 3DOX
			CopyMemory(Result, &SpoofedExecutionId, sizeof(XEX_EXECUTION_ID));
			break;
		}
	}
	else if (imageKey == 0x40006 && !Result)
		Result = &SpoofedExecutionId;
	return Result;
}
NTSTATUS XexLoadExecutableHook(PCHAR Name, PHANDLE Handle, DWORD TypeFlags, DWORD Version) {
	HANDLE Module = 0;
	NTSTATUS Result = XexLoadExecutable(Name, &Module, TypeFlags, Version);
	if (Handle != 0) *Handle = Module;
	if (NT_SUCCESS(Result)) InitializeTitleHooks((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle);
	return Result;
}
NTSTATUS XexLoadImageHook(CONST PCHAR Name, DWORD TypeFlags, DWORD Version, PHANDLE Handle)
{
	HANDLE Module = 0;
	NTSTATUS Result = XexLoadImage(Name, TypeFlags, Version, &Module);
	if (Handle != 0) *Handle = Module;
	if (NT_SUCCESS(Result)) InitializeTitleHooks((PLDR_DATA_TABLE_ENTRY)Module);
	return Result;
}
DWORD XeKeysExecuteHook(BYTE* pBuffer, DWORD respSize, BYTE* HvSalt, PVOID r6, PVOID r7, PVOID r8) {

	WORD BLDR_FLAGS = 0xD83E;
	WORD BLDR_FLAGS_KV1 = (~0x20);

	*(DWORD*)0x80108520 = 0x38000042;
	*(DWORD*)0x80108524 = 0x44000002;
	*(DWORD*)0x80108528 = 0x4E800020;

	BYTE* consoleHv = (BYTE*)XPhysicalAlloc(0x40000, MAXULONG_PTR, 0, PAGE_READWRITE);

	HvxPeekBytes(0x8000010000000000, consoleHv, 0x10000);
	HvxPeekBytes(0x8000010200010000, consoleHv + 0x10000, 0x10000);
	HvxPeekBytes(0x8000010400020000, consoleHv + 0x20000, 0x10000);
	HvxPeekBytes(0x8000010600030000, consoleHv + 0x30000, 0x10000);

	*(WORD*)(cleanHv + 0x6) = (kvtype == FALSE) ? ((WORD)(BLDR_FLAGS & BLDR_FLAGS_KV1)) : BLDR_FLAGS;
	*(DWORD*)(cleanHv + 0x14) = UpdateSequence;
	*(DWORD*)(cleanHv + 0x30) = HVSF();
	*(DWORD*)(cleanHv + 0x74) = kvCbFlag;
	memcpy(cleanHv + 0x20, consoleHv + 0x20, 0x10);

	memcpy(cleanHv + 0x10000, consoleHv + 0x10000, 0xC0);
	memcpy(cleanHv + 0x10100, consoleHv + 0x10100, 0x30);
	memcpy(cleanHv + 0x16390, consoleHv + 0x16390, 0x04);
	memcpy(cleanHv + 0x16620, consoleHv + 0x16620, 0x01);
	memcpy(cleanHv + 0x16640, consoleHv + 0x16640, 0x14);
	memcpy(cleanHv + 0x16710, consoleHv + 0x16710, 0x10);
	memcpy(cleanHv + 0x16980, consoleHv + 0x16980, 0x102);
	memcpy(cleanHv + 0x16B90, consoleHv + 0x16B90, 0x10);
	memcpy(cleanHv + 0x16E98, consoleHv + 0x16E98, 0x4);

	HvxPokeBytes(0x8000010000000000, cleanHv, 0x10000);
	HvxPokeBytes(0x8000010200010000, cleanHv + 0x10000, 0x10000);
	HvxPokeBytes(0x8000010400020000, cleanHv + 0x20000, 0x10000);
	HvxPokeBytes(0x8000010600030000, cleanHv + 0x30000, 0x10000);

	xeKeysExecute((BYTE*)pBuffer, (DWORD)respSize, (PVOID)mmGetPhysicalAddress(HvSalt), (QWORD*)0x0002000044970000, 0, 0);

	*(DWORD*)(pBuffer + 0x30) = 0x07600000;
	*(QWORD*)(pBuffer + 0x40) = 0x0000000200000000;
	*(QWORD*)(pBuffer + 0x48) = 0x0000010000000000;
	memcpy(pBuffer + 0x64, CPUKeyDigest, 0x14);

	HvxPokeBytes(0x8000010000000000, consoleHv, 0x10000);
	HvxPokeBytes(0x8000010200010000, consoleHv + 0x10000, 0x10000);
	HvxPokeBytes(0x8000010400020000, consoleHv + 0x20000, 0x10000);
	HvxPokeBytes(0x8000010600030000, consoleHv + 0x30000, 0x10000);
	XPhysicalFree(consoleHv);

	!Crl ? XNotifyQueueUI(XNOTIFYUI_TYPE_COMPLAINT, 0, 2, L"[Silent] Connected to Xbox Live!", 0), Crl = TRUE : NULL;

	SWriteFile("HDD:\\XKE_resp.bin", pBuffer, 0x100);

	return 0;
}
DWORD HalSendSMCMessageHook(LPVOID pRecvBuffer)
{
	memset(pRecvBuffer, 0x00, 0x10);
	memcpy(pRecvBuffer, spoofSMCKey, 0x5);
	return 0;
}

NTSTATUS GetSecurityInfo(XOSC_BUFFER* Response)
{
	HANDLE moduleHandle;
	WORD wvalue = 1;
	PLDR_DATA_TABLE_ENTRY pldr_dat;
	BYTE securityDigest[0x14];
	WORD unkwordt[8];
	BYTE smcResp[0x10];
	memset(unkwordt, 0, 16);
	unkwordt[7] = unkwordt[7] & 0xF8;

	Response->hvUnknown = 0;
	Response->secDataDvdBootFailures = 0;
	Response->kvRestrictedStatus = 0x00070000;
	Response->secDataFuseBlowFailures = 0;
	Response->secDataDvdAuthExFailures = 0;
	Response->secDataDvdAuthExTimeouts = 0;
	Response->kvRestrictedPrivs = 0;
	Response->hvSecurityDetected = 0;
	Response->hvSecurityActivated = 0;

	memcpy(securityDigest, (BYTE*)0x8E03AA40, 0x14);

	XECRYPT_SHA_STATE xamxSha;
	XeCryptShaInit(&xamxSha);
	memcpy(&xamxSha, xam_da, sizeof(XECRYPT_SHA_STATE));
	XeCryptShaUpdate(&xamxSha, securityDigest, 0x14);
	XeCryptShaUpdate(&xamxSha, (BYTE*)unkwordt, 0x10);
	XeCryptShaFinal(&xamxSha, securityDigest, 0x14);

	WORD unkword = 0;
	BYTE macaddress[6];

	if (NT_SUCCESS(ExGetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, macaddress, 6, &unkword)))
	{
		XECRYPT_SHA_STATE xkernelsha;
		XeCryptShaInit(&xkernelsha);
		memcpy(&xkernelsha, kernel_da, sizeof(XECRYPT_SHA_STATE));
		XeCryptShaUpdate(&xkernelsha, securityDigest, 0x14);
		XeCryptShaUpdate(&xkernelsha, (BYTE*)macaddress, 0x6);
		XeCryptShaFinal(&xkernelsha, securityDigest, 0x14);
		wvalue |= 2;
	}

	if (NT_SUCCESS(XexGetModuleHandle(NULL, &moduleHandle))) // NULL is = handle current title
	{
		PIMAGE_XEX_HEADER xheaders;
		pldr_dat = (PLDR_DATA_TABLE_ENTRY)moduleHandle;
		xheaders = (PIMAGE_XEX_HEADER)pldr_dat->XexHeaderBase;
		if (xheaders != NULL)
		{
			BYTE* bytetmp = (BYTE*)(xheaders->SecurityInfo + 0x17C);
			WORD wsize = xheaders->SizeOfHeaders - ((DWORD)bytetmp - (DWORD)xheaders);
			HalSendSMCMessageHook(smcResp);
			XEX_EXECUTION_ID* pExeId;
			XamGetExecutionId(&pExeId);

			if (pExeId->TitleID == 0xFFFE07D1 || pExeId->TitleID == 0xFFFF0055 || pExeId->TitleID == 0xC0DE9999 || pExeId->TitleID == 0xFFFE07FF || pExeId->TitleID == 0xF5D20000 || pExeId->TitleID == 0xFFFF011D || pExeId->TitleID == 0x00000166
				|| pExeId->TitleID == 0x00000189 || pExeId->TitleID == 0x00000188 || pExeId->TitleID == 0x00000176 || pExeId->TitleID == 0x00000167 || pExeId->TitleID == 0x00000177 || pExeId->TitleID == 0x00000170
				|| pExeId->TitleID == 0xFFFEFF43 || pExeId->TitleID == 0xFEEDC0DE || pExeId->TitleID == 0x00000001 || pExeId->TitleID == 0x00000171 || pExeId->TitleID == 0xFFED0707
				|| pExeId->TitleID == 0x00000000 || pExeId->TitleID == 0x1CED2911 || pExeId->TitleID == 0xFFED7300 || pExeId->TitleID == 0x00FBAFBA || pExeId->TitleID == 0x000003D0)
			{
				memcpy(Response->xexExecutionId, dashExid, 0x18);

				XECRYPT_SHA_STATE xsha;
				XeCryptShaInit(&xsha);
				memcpy(&xsha, dash_da, sizeof(XECRYPT_SHA_STATE));
				XeCryptShaUpdate(&xsha, securityDigest, 0x14);
				XeCryptShaUpdate(&xsha, smcResp, 0x5);
				XeCryptShaFinal(&xsha, securityDigest, 0x14);
			}
			else
			{
				XECRYPT_SHA_STATE xsha;
				XeCryptShaInit(&xsha);
				XeCryptShaUpdate(&xsha, bytetmp, wsize);
				XeCryptShaUpdate(&xsha, securityDigest, 0x14);
				XeCryptShaUpdate(&xsha, smcResp, 0x5);
				XeCryptShaFinal(&xsha, securityDigest, 0x14);
			}
			wvalue |= 4;
		}
	}
	XeCryptSha((PBYTE)0x900101A3, 0x8E59, securityDigest, 0x14, 0, 0, securityDigest, 0x14);
	securityDigest[0] = (unkwordt[7] | wvalue) & 0xFF;
	memcpy(Response->xexHashing, securityDigest, 0x10);
	memcpy(Response->zeroEncryptedConsoleType, (PVOID)0x8E03AA50, 0x10);
	return 0;
}
void NetDll_XnpLogonSetChallengeResponseHook(XNCALLER_TYPE xnc, DWORD r4, PXOSC_BUFFER Response, DWORD bufferSize) {
	KEY_VAULT kv2;
	memset(Response, 0, bufferSize);
	memset(Response, 0xAA, 0x2E0);

	BYTE* KV = (BYTE*)XPhysicalAlloc(0x4000, MAXULONG_PTR, 0, PAGE_READWRITE);
	memcpy(KV, &kv2, 0x4000);

	XEX_EXECUTION_ID* ExecutionID;
	XamGetExecutionId(&ExecutionID);

	int HV_PROTECTED_FLAGS_NONE = 0;
	int HV_PROTECTED_FLAGS_NO_EJECT_REBOOT = 1;
	int HV_PROTECTED_FLAGS_AUTH_EX_CAP = 4;

	QWORD HvProtectedFlags = *(QWORD*)0x8E038678;
	QWORD HV_PROTECTED_FLAGS = HV_PROTECTED_FLAGS_AUTH_EX_CAP | (((HvProtectedFlags & HV_PROTECTED_FLAGS_NO_EJECT_REBOOT) == HV_PROTECTED_FLAGS_NO_EJECT_REBOOT) ? HV_PROTECTED_FLAGS_NO_EJECT_REBOOT : HV_PROTECTED_FLAGS_NONE);

	DWORD flash_size = *(DWORD*)(KV + 0x24);

	WORD BLDR_FLAGS = 0xD83E;
	WORD BLDR_FLAGS_KV1 = (~0x20);

	DWORD HvKeysStatusFlags = 0x023289D3;
	if (Crl) HvKeysStatusFlags |= 0x10000;
	if (Fcrt) HvKeysStatusFlags |= 0x1000000;

	Response->dwResult = 0;
	Response->MajorVersion = 9;
	Response->MinorVersion = 2;
	Response->qwflags = 0x00000000000001BF;
	Response->DvdInqResp = 0;
	Response->XeikaInqResp = 0;
	Response->executionIdResponse = 0;
	Response->HvIdCacheDataResp = 0;
	Response->MediaInfoResp = 0xC8003003;
	Response->MediaInfodwUnk1 = 0xAAAAAAAA;
	Response->MediaInfodwUnk2 = 0xAAAAAAAA;
	Response->MediaInfoAbUnk = 0xAAAAAAAA;
	Response->MediaInfoPad5 = 0xAAAAAAAA;
	Response->HwMaskTemplate = 0x40000012;
	memcpy(Response->xexExecutionId, ExecutionID, 0x18);
	memcpy(Response->hvCpuKeyHash, CPUKeyDigest, 0x10);
	memset(Response->DvdXeikaPhaseLevel, 0, 0x3);
	Response->drivePhaseLevel = *(BYTE*)(KV + 0xC89);
	Response->dwMediaType = 0;
	Response->dwTitleId = 0;
	memset(Response->DvdPfiInfo, 0xAA, 0x11);
	memset(Response->DvdDmiMediaSerial, 0xAA, 0x20);
	memset(Response->DvdMediaId1, 0xAA, 0x10);
	memset(Response->abPad, 0xAA, 0x03);
	Response->DvdDmi10Data = 0xAAAAAAAAAAAAAAAA;
	Response->DvdGeometrySectors = 0xAAAAAAAA;
	Response->DvdGeometryBytesPerSector = 0xAAAAAAAA;
	memset(Response->DvdMediaId2, 0xAA, 0x10);
	memcpy(Response->DvdInqRespData, KV + 0xC8A, 0x24);
	memcpy(Response->XeikaInqData, KV + 0xC8A, 0x24);
	memcpy(Response->consoleSerial, KV + 0xB0, 0xC);
	Response->serialByte = 0x00AA;
	Response->hvHeaderFlags = (kvtype == FALSE) ? ((WORD)(BLDR_FLAGS & BLDR_FLAGS_KV1)) : BLDR_FLAGS;
	Response->hvUnrestrictedPrivs = *(WORD*)(KV + 0xC8);
	Response->kvOddFeatures = *(WORD*)(KV + 0x1C);
	Response->kvPolicyFlashSize = flash_size;
	Response->hvKeyStatus = HvKeysStatusFlags;
	memset(&Response->dwPad1, 0xAA, 0x4);
	memset(&Response->dwPad2, 0xAA, 0x4);
	Response->HardwareMask = kvPcieFlag;
	Response->hvProtectedFlags = HV_PROTECTED_FLAGS;
	memcpy(Response->consoleId, KV + 0x9CA, 0x5);
	memset(Response->_unk14, 0, 0x2B);
	Response->XboxHardwareInfoFlags = kvHardwareFlag;
	memset(Response->HddSerialNumber, 0, 0x14);
	memset(Response->HddFirmwareRevision, 0, 0x08);
	memset(Response->HddModelNumber, 0, 0x28);
	memset(Response->HddUserAddressableSectors, 0, 0x04);
	memset(Response->unkMediaInfo, 0xAA, 0x80);
	Response->DvdUnkp1 = 0xAAAAAAAAAAAAAAAA;
	Response->MediaInfoUnkp3 = 0xAAAAAAAA;
	Response->MemoryUnit0 = 0;
	Response->MemoryUnit1 = 0;
	Response->InMuSfcAu = 0;
	Response->IntMuUSBAu = 0;
	Response->UsbMu0PartitionFileSize = 0x00020000;
	Response->UsbMu1PartitionFileSize = 0;
	Response->UsbMu2PartitionFileSize = 0;
	Response->crlVersion = 6;
	Response->Layer0PfiSectors = 0xAAAAAAAAAAAAAAAA;
	Response->Layer1PfiSectors = 0xAAAAAAAAAAAAAAAA;
	Response->respMagic = 0x5F534750;
	memset(&Response->dwFinalPad, 0xAA, 0x4);
	memset(&Response->NulledBuffer, 0, 0x120);

	GetSecurityInfo(Response);

	XPhysicalFree(KV);
	SWriteFile("HDD:\\xosc_resp.bin", Response, bufferSize);
	XNotifyQueueUI(XNOTIFYUI_TYPE_COMPLAINT, 0, 2, L"[Silent] XOSC Success!", 0);
	NetDll_XnpLogonSetChallengeResponseOriginal.callOriginal(xnc, r4, Response, bufferSize);
}
BYTE PATCH_DATA_KXAM_RETAIL[88] = {
	0x81, 0x67, 0x98, 0xEC, 0x00, 0x00, 0x00, 0x01, 0x60, 0x00, 0x00, 0x00, 0x81, 0x67, 0xC4, 0xB4,
	0x00, 0x00, 0x00, 0x01, 0x38, 0x60, 0x00, 0x00, 0x81, 0x67, 0xF9, 0x78, 0x00, 0x00, 0x00, 0x01,
	0x38, 0x60, 0x00, 0x00, 0x81, 0x68, 0x25, 0x44, 0x00, 0x00, 0x00, 0x01, 0x60, 0x00, 0x00, 0x00,
	0x81, 0x6D, 0xAC, 0x84, 0x00, 0x00, 0x00, 0x01, 0x38, 0x60, 0x00, 0x06, 0x81, 0x92, 0xBD, 0xA8,
	0x00, 0x00, 0x00, 0x01, 0x38, 0x60, 0x00, 0x00, 0x81, 0xA3, 0xCD, 0x60, 0x00, 0x00, 0x00, 0x01,
	0x38, 0x60, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
};
BOOL InitializeSystemHooks() {
	applyPatches(PATCH_DATA_KXAM_RETAIL);
	if (PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 0x12B, (DWORD)RtlImageXexHeaderFieldHook) != S_OK) return FALSE;
	if (PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 0x198, (DWORD)XexLoadExecutableHook) != S_OK) return FALSE;
	if (PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 0x199, (DWORD)XexLoadImageHook) != S_OK) return FALSE;
	if (PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 0x25F, (DWORD)XeKeysExecuteHook) != S_OK) return FALSE;
	NetDll_XnpLogonSetChallengeResponseOriginal.setupDetour(0x817417B0, NetDll_XnpLogonSetChallengeResponseHook);
	return TRUE;
}