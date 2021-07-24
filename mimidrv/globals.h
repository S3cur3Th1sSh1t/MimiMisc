/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include <ntifs.h>
#include <fltkernel.h>
#include <ntddk.h>
#include <aux_klib.h>
#include <ntstrsafe.h>
#include <string.h>
#include "ioctl.h"

#define POOL_TAG	'pjbP'
#define MIMIDRV		L"mimidrv"

#define kprintf(ceFdBuffer, Format, ...) (RtlStringCbPrintfExW(*(ceFdBuffer)->Buffer, *(ceFdBuffer)->szBuffer, (ceFdBuffer)->Buffer, (ceFdBuffer)->szBuffer, STRSAFE_NO_TRUNCATION, Format, __VA_ARGS__))

extern char * PsGetProcessImageFileName(PEPROCESS monProcess);
extern NTSYSAPI NTSTATUS NTAPI ZwSetInformationProcess (__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass, __in_bcount(ProcessInformationLength) PVOID ProcessInformation, __in ULONG ProcessInformationLength);
extern NTSYSAPI NTSTATUS NTAPI ZwUnloadKey(IN POBJECT_ATTRIBUTES DestinationKeyName); 

typedef struct _JoAA_BUFFER {
	size_t * szBuffer;
	PWSTR * Buffer;
} JoAA_BUFFER, *PJoAA_BUFFER;

typedef enum _JoAA_OS_INDEX {
	ceFdOsIndex_UNK		= 0,
	ceFdOsIndex_XP		= 1,
	ceFdOsIndex_2K3		= 2,
	ceFdOsIndex_VISTA	= 3,
	ceFdOsIndex_7		= 4,
	ceFdOsIndex_8		= 5,
	ceFdOsIndex_BLUE	= 6,
	ceFdOsIndex_10_1507	= 7,
	ceFdOsIndex_10_1511	= 8,
	ceFdOsIndex_10_1607	= 9,
	ceFdOsIndex_10_1703	= 10,
	ceFdOsIndex_10_1709	= 11,
	ceFdOsIndex_10_1803	= 12,
	ceFdOsIndex_10_1809	= 13,
	ceFdOsIndex_10_1903	= 14,
	ceFdOsIndex_10_1909	= 15,
	ceFdOsIndex_10_2004	= 16,
	ceFdOsIndex_MAX		= 17,
} JoAA_OS_INDEX, *PJoAA_OS_INDEX;

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
#define EX_FAST_REF_MASK	0x0f
#elif defined(_M_IX86)
#define EX_FAST_REF_MASK	0x07
#endif

#define JoAA_mask3bits(addr)	 (((ULONG_PTR) (addr)) & ~7)

JoAA_OS_INDEX ceFdOsIndex;