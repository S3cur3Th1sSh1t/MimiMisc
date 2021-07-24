/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "kkllclqlssdt.h"

#if defined(_M_X64)
PSERVICE_DESCRIPTOR_TABLE			KeServiceDescriptorTable = NULL;
#endif

NTSTATUS kkllclqlssdt_list(PJoAA_BUFFER outBuffer)
{
	NTSTATUS status;
	USHORT idxFunction;
	ULONG_PTR funcAddr;

#if defined(_M_X64)
	status = kkllclqlssdt_getKeServiceDescriptorTable();
	if(NT_SUCCESS(status))
	{
#endif
		status = kprintf(outBuffer, L"KeServiceDescriptorTable : 0x%p (%u)\n", KeServiceDescriptorTable, KeServiceDescriptorTable->TableSize);
		for(idxFunction = 0; (idxFunction < KeServiceDescriptorTable->TableSize) && NT_SUCCESS(status) ; idxFunction++)
		{
#if defined(_M_IX86)
			funcAddr = (ULONG_PTR) KeServiceDescriptorTable->ServiceTable[idxFunction];
#else
			funcAddr = (ULONG_PTR) KeServiceDescriptorTable->OffsetToService;
			if(ceFdOsIndex < ceFdOsIndex_VISTA)
				funcAddr += KeServiceDescriptorTable->OffsetToService[idxFunction] & ~EX_FAST_REF_MASK;
			else
				funcAddr += KeServiceDescriptorTable->OffsetToService[idxFunction] >> 4;
#endif
			status = kprintf(outBuffer, L"[%5u] ", idxFunction);
			if(NT_SUCCESS(status))
				status = kkllclqlmodules_fromAddr(outBuffer, (PVOID) funcAddr);
		}
#if defined(_M_X64)
	}
#endif
	return status;
}

#if defined(_M_X64)
const UCHAR PTRN_WALL_Ke[]	= {/*0x00, 0x00, 0x4d, 0x0f, 0x45,*/ 0xd3, 0x42, 0x3b, 0x44, 0x17, 0x10, 0x0f, 0x83};
const UCHAR PTRN_W1803_Ke[] = {0xd3, 0x41, 0x3b, 0x44, 0x3a, 0x10, 0x0f, 0x83};
const LONG OFFS_WNO8_Ke		= -24;//-19;
const LONG OFFS_WIN8_Ke		= -21;//-16;
const LONG OFFS_WIN10A_Ke	= -38;//-16;
NTSTATUS kkllclqlssdt_getKeServiceDescriptorTable()
{
	NTSTATUS status = STATUS_NOT_FOUND;
	if(KeServiceDescriptorTable)
		status = STATUS_SUCCESS;
	else
	{
		status = kkllclqlmemory_genericPointerSearch(
			(PUCHAR *) &KeServiceDescriptorTable,
			((PUCHAR) ZwUnloadKey) - (21 * PAGE_SIZE),
			((PUCHAR) ZwUnloadKey) + (19 * PAGE_SIZE),
			(ceFdOsIndex < ceFdOsIndex_10_1803) ? PTRN_WALL_Ke : PTRN_W1803_Ke,
			(ceFdOsIndex < ceFdOsIndex_10_1803) ? sizeof(PTRN_WALL_Ke) : sizeof(PTRN_W1803_Ke),
			(ceFdOsIndex < ceFdOsIndex_8) ? OFFS_WNO8_Ke : (ceFdOsIndex < ceFdOsIndex_10_1607) ? OFFS_WIN8_Ke : OFFS_WIN10A_Ke);
	}
	return status;
}
#endif