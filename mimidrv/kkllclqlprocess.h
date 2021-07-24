/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"

typedef enum _JoAA_PROCESS_INDEX {
	EprocessNext	= 0,
	EprocessFlags2	= 1,
	TokenPrivs		= 2,
	SignatureProtect= 3,

	Eprocess_MAX	= 4,
} JoAA_PROCESS_INDEX, *PJoAA_PROCESS_INDEX;

typedef struct _JoAA_NT6_PRIVILEGES {
	UCHAR Present[8];
	UCHAR Enabled[8];
	UCHAR EnabledByDefault[8];
} JoAA_NT6_PRIVILEGES, *PJoAA_NT6_PRIVILEGES;

#define TOKEN_FROZEN_MASK		0x00008000
#define PROTECTED_PROCESS_MASK	0x00000800

typedef NTSTATUS (* PKKLL_M_PROCESS_CALLBACK) (SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, PEPROCESS pProcess, PVOID pvArg);
NTSTATUS kkllclqlprocess_enum(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, PKKLL_M_PROCESS_CALLBACK callback, PVOID pvArg);

NTSTATUS kkllclqlprocess_token(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer);
NTSTATUS kkllclqlprocess_protect(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer);
NTSTATUS kkllclqlprocess_fullprivileges(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer);

NTSTATUS kkllclqlprocess_token_toProcess(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, HANDLE hSrcToken, PEPROCESS pToProcess);

NTSTATUS kkllclqlprocess_list_callback(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, PEPROCESS pProcess, PVOID pvArg);
NTSTATUS kkllclqlprocess_systoken_callback(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, PEPROCESS pProcess, PVOID pvArg);