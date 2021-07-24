/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"

typedef NTSTATUS (* PKKLL_M_MODULE_CALLBACK) (SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, PAUX_MODULE_EXTENDED_INFO pModule, PVOID pvArg, BOOLEAN * mustContinue);

typedef struct _KKLL_M_MODULE_FROM_ADDR {
	BOOLEAN isFound;
	ULONG_PTR addr;
} KKLL_M_MODULE_FROM_ADDR, *PKKLL_M_MODULE_FROM_ADDR;

typedef struct _KKLL_M_MODULE_BASIC_INFOS {
	PUCHAR addr;
	SIZE_T size;
} KKLL_M_MODULE_BASIC_INFOS, *PKKLL_M_MODULE_BASIC_INFOS;

NTSTATUS kkllclqlmodules_enum(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, PKKLL_M_MODULE_CALLBACK callback, PVOID pvArg);

NTSTATUS kkllclqlmodules_list_callback(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, PAUX_MODULE_EXTENDED_INFO pModule, PVOID pvArg, BOOLEAN * mustContinue);

NTSTATUS kkllclqlmodules_fromAddr(PJoAA_BUFFER outBuffer, PVOID addr);
NTSTATUS kkllclqlmodules_fromAddr_callback(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, PAUX_MODULE_EXTENDED_INFO pModule, PVOID pvArg, BOOLEAN * mustContinue);

NTSTATUS kkllclqlmodules_first_callback(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, PAUX_MODULE_EXTENDED_INFO pModule, PVOID pvArg, BOOLEAN * mustContinue);