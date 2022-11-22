#pragma once
#include "stdafx.h"
#pragma pack(push, 1)
typedef enum _ODD_POLICY {
	ODD_POLICY_FLAG_CHECK_FIRMWARE = 0x120
} ODD_POLICY;
typedef union _INQUIRY_DATA {
	struct {
		BYTE DeviceType : 5;
		BYTE DeviceTypeQualifier : 3;
		BYTE DeviceTypeModifier : 7;
		BYTE RemovableMedia : 1;
		BYTE Versions : 8;
		BYTE ResponseDataFormat : 4;
		BYTE HiSupport : 1;
		BYTE NormACA : 1;
		BYTE ReservedBYTE : 1;
		BYTE AERC : 1;
		BYTE AdditionalLength : 8;
		WORD ReservedWORD : 16;
		BYTE SoftReset : 1;
		BYTE CommandQueue : 1;
		BYTE ReservedBYTE2 : 1;
		BYTE LinkedCommands : 1;
		BYTE Synchronous : 1;
		BYTE Wide16Bit : 1;
		BYTE Wide32Bit : 1;
		BYTE RelativeAddressing : 1;
		BYTE VendorId[0x8];
		BYTE ProductId[0x10];
		BYTE ProductRevisionLevel[0x4];
	};
	BYTE Data[0x24];
} INQUIRY_DATA, *PINQUIRY_DATA;
typedef struct _XEIKA_ODD_DATA {
	BYTE Version;
	BYTE PhaseLevel;
	INQUIRY_DATA InquiryData;
} XEIKA_ODD_DATA, *PXEIKA_ODD_DATA;
typedef struct _XEIKA_DATA {
	XECRYPT_RSAPUB_2048 PublicKey;
	DWORD Signature;
	WORD Version;
	XEIKA_ODD_DATA OddData;
	BYTE Padding[0x4];
} XEIKA_DATA, *PXEIKA_DATA;
typedef struct _XEIKA_CERTIFICATE {
	WORD Size;
	XEIKA_DATA Data;
	BYTE Padding[0x1146];
} XEIKA_CERTIFICATE, *PXEIKA_CERTIFICATE;
typedef struct _KEY_VAULT {
	BYTE HmacShaDigest[0x10];
	BYTE Confounder[0x8];
	BYTE ManufacturingMode;
	BYTE AlternateKeyVault;
	BYTE RestrictedPrivilegesFlags;
	BYTE ReservedBYTE;
	WORD OddFeatures;
	WORD OddAuthType;
	DWORD RestrictedHVExtLoader;
	DWORD PolicyFlashSize;
	DWORD PolicyBuiltInUSBMUSize;
	DWORD ReservedDWORD;
	QWORD RestrictedPrivileges;
	QWORD ReservedQWORD;
	QWORD ReservedQWORD2;
	QWORD ReservedQWORD3;
	BYTE ReservedKey[0x10];
	BYTE ReservedKey2[0x10];
	BYTE ReservedKey3[0x10];
	BYTE ReservedKey4[0x10];
	BYTE ReservedRandomKey[0x10];
	BYTE ReservedRandomKey2[0x10];
	BYTE ConsolSerialNumber[0xC];
	BYTE MotherboardSerialNumber[0xC];
	WORD GameRegion;
	BYTE Padding[0x6];
	BYTE ConsoleObfuscationKey[0x10];
	BYTE KeyObfuscationKey[0x10];
	BYTE RoamableObfuscationKey[0x10];
	BYTE DvdKey[0x10];
	BYTE PrimaryActivationKey[0x18];
	BYTE SecondaryActivationKey[0x10];
	BYTE Padding2[0x160];
	XECRYPT_RSAPRV_1024 ConsolePrivateKey;
	XECRYPT_RSAPRV_2048 XeikaPrivateKey;
	XECRYPT_RSAPRV_1024 CardeaPrivateKey;
	XE_CONSOLE_CERTIFICATE ConsoleCertificate;
	XEIKA_CERTIFICATE XeikaCertificate;
	BYTE KeyVaultSignature[0x100];
	BYTE CardeaCertificate[0x2108];
} KEY_VAULT, *PKEY_VAULT;
#pragma pack(pop)