#include "stdafx.h"
#define HvxPeekPokeExpID 0x48565050
extern VOID NotifyPopup(PWCHAR myPWCHAR);
HRESULT CreateSymbolicLink(CHAR* szDrive, CHAR* szDeviceName, BOOL System);
FARPROC ResolveFunction(CHAR* ModuleName, DWORD Ordinal);
BOOL SWriteFile(CONST PCHAR FilePath, CONST PVOID Buffer, DWORD Size);
//BOOL SReadFile(CONST PCHAR FilePath, MemoryBuffer &Buffer);
BOOL TrayOpen();
/*Mount Path*/
extern PCHAR PATH_KV;
extern PCHAR PATH_CPU_BIN;
extern PCHAR PATH_XEX;
extern PCHAR PATH_INI;
extern BOOL InitializeHvxPeekPoke();
extern BYTE HvxPeekBYTE(QWORD Address);
extern WORD HvxPeekWORD(QWORD Address);
extern DWORD HvxPeekDWORD(QWORD Address);
extern QWORD HvxPeekQWORD(QWORD Address);
extern DWORD HvxPeekBytes(QWORD Address, PVOID Buffer, DWORD Size);
extern DWORD HvxPokeBYTE(QWORD Address, BYTE Value);
extern DWORD HvxPokeWORD(QWORD Address, WORD Value);
extern DWORD HvxPokeDWORD(QWORD Address, DWORD Value);
extern DWORD HvxPokeQWORD(QWORD Address, QWORD Value);
extern DWORD HvxPokeBytes(QWORD Address, CONST PVOID Buffer, DWORD Size);
extern BYTE CurrentMACAddress[0x6];
extern BYTE SpoofedMACAddress[0x6];
extern BOOL DashLoaded;
extern BYTE CPUKey[0x10];
extern BYTE KVCPUKey[0x10];
extern BYTE CPUKeyDigest[0x14];
extern BYTE KVDigest[0x14];
extern BOOL Crl, Fcrt, kvtype;
extern DWORD UpdateSequence;
extern DWORD kvCbFlag;
extern DWORD kvHardwareFlag;
extern QWORD kvPcieFlag;
extern DWORD dwUpdateSequence;
extern BYTE kvFuseKey[0xC];
extern BYTE spoofSMCKey[0x5];
extern BYTE coronaKey[0xC];
extern BYTE falconKey[0xC];
extern BYTE jasperKey[0xC];
extern BYTE trinityKey[0xC];
extern BYTE zephyrKey[0xC];
extern BYTE xenonKey[0xC];
extern BYTE coronaSMC[5];
extern BYTE trinitySMC[5];
extern BYTE jasperSMC[5];
extern BYTE falconSMC[5];
extern BYTE zephyrSMC[5];
extern BYTE xenonSMC[5];
VOID PatchInJump(PDWORD Address, DWORD Destination, BOOL Linked);
DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, PCHAR Import, DWORD Ordinal, DWORD Destination);
DWORD PatchModuleImport(PCHAR Module, PCHAR Import, DWORD Ordinal, DWORD Destination);
BOOL SetKeyVault();
DWORD applyPatches(VOID* patches);
typedef HRESULT(*pDmSetMemory)(LPVOID lpbAddr, DWORD cb, LPCVOID lpbBuf, LPDWORD pcbRet);
#define HvCall QWORD __declspec(naked)

class MemoryBuffer {
public:

	MemoryBuffer(DWORD Size = 0x200)
	{
		m_Buffer = 0;
		m_DataLength = 0;
		m_BufferSize = 0;
		if ((Size != 0) && (Size < UINT_MAX))
		{
			m_Buffer = (PBYTE)malloc(Size + 1);
			if (m_Buffer)
			{
				m_BufferSize = Size;
				m_Buffer[0] = 0;
			}
		}
	}
	~MemoryBuffer()
	{
		if (m_Buffer) free(m_Buffer);
		m_Buffer = 0;
		m_DataLength = 0;
		m_BufferSize = 0;
	}
	BOOL CheckSize(DWORD Size)
	{
		if (m_BufferSize >= (m_DataLength + Size)) return TRUE;
		else
		{
			DWORD NewSize = max((m_DataLength + Size), (m_BufferSize * 2));
			PBYTE NewBuffer = (PBYTE)realloc(m_Buffer, NewSize + 1);
			if (NewBuffer)
			{
				m_BufferSize = NewSize;
				m_Buffer = NewBuffer;
				return TRUE;
			}
			else return FALSE;
		}
	}
	VOID Add(CONST PVOID Buffer, DWORD Size)
	{
		if (CheckSize(Size))
		{
			memcpy(m_Buffer + m_DataLength, Buffer, Size);
			m_DataLength += Size;
			*(m_Buffer + m_DataLength) = 0;
		}
	}
	DWORD GetLength() CONST
	{
		return m_DataLength;
	}
	PBYTE GetBuffer() CONST
	{
		return m_Buffer;
	}
private:
	PBYTE m_Buffer;
	DWORD m_DataLength;
	DWORD m_BufferSize;
};

enum PEEK_POKE_TYPE {
	PEEK_BYTE = 0x0,
	PEEK_WORD = 0x1,
	PEEK_DWORD = 0x2,
	PEEK_QWORD = 0x3,
	PEEK_BYTES = 0x4,
	POKE_BYTE = 0x5,
	POKE_WORD = 0x6,
	POKE_DWORD = 0x7,
	POKE_QWORD = 0x8,
	POKE_BYTES = 0x9,
	PEEK_SPR = 0xA
};
static HvCall HvxExpansionInstall(DWORD PhysicalAddress, DWORD CodeSize) {
	__asm {
		li			r0, 0x72
		sc
		blr
	}
}
static HvCall HvxExpansionCall(DWORD ExpansionId, QWORD Param1 = 0, QWORD Param2 = 0, QWORD Param3 = 0, QWORD Param4 = 0) {
	__asm {
		li			r0, 0x73
		sc
		blr
	}
}