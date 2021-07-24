/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kkllclqlmodules.h"
#include "kkllclqlmemory.h"

typedef struct _SERVICE_DESCRIPTOR_TABLE {
#if defined(_M_IX86)
	PVOID	*ServiceTable;
#elif defined(_M_X64)
	LONG	*OffsetToService;
#endif
	PULONG	CounterTable;
	ULONG	TableSize;
	PUCHAR	ArgumentTable;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

#if defined(_M_IX86)
	extern PSERVICE_DESCRIPTOR_TABLE	KeServiceDescriptorTable;
#elif defined(_M_X64)
	PSERVICE_DESCRIPTOR_TABLE			KeServiceDescriptorTable;
	NTSTATUS kkllclqlssdt_getKeServiceDescriptorTable();
#endif

NTSTATUS kkllclqlssdt_list(PJoAA_BUFFER outBuffer);