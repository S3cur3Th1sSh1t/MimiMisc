/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kwindbg.h"
#include <bcrypt.h>

typedef struct _JoAA_HARD_KEY {
	ULONG cbSecret;
	BYTE data[ANYSIZE_ARRAY]; // etc...
} JoAA_HARD_KEY, *PJoAA_HARD_KEY;

typedef struct _JoAA_BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	JoAA_HARD_KEY hardkey;
} JoAA_BCRYPT_KEY, *PJoAA_BCRYPT_KEY;

typedef struct _JoAA_BCRYPT_KEY8 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	PVOID unk4;	// before, align in x64
	JoAA_HARD_KEY hardkey;
} JoAA_BCRYPT_KEY8, *PJoAA_BCRYPT_KEY8;

typedef struct _JoAA_BCRYPT_KEY81 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2; 
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	JoAA_HARD_KEY hardkey;
} JoAA_BCRYPT_KEY81, *PJoAA_BCRYPT_KEY81;

typedef struct _JoAA_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	PJoAA_BCRYPT_KEY key;
	PVOID unk0;
} JoAA_BCRYPT_HANDLE_KEY, *PJoAA_BCRYPT_HANDLE_KEY;

typedef struct _JoAA_BCRYPT_GEN_KEY {
	BCRYPT_ALG_HANDLE hProvider;
	BCRYPT_KEY_HANDLE hKey;
	PBYTE pKey;
	ULONG cbKey;
} JoAA_BCRYPT_GEN_KEY, *PJoAA_BCRYPT_GEN_KEY;

NTSTATUS kcpdclqlsekurlsa_nt6_init();
NTSTATUS kcpdclqlsekurlsa_nt6_clean();

NTSTATUS kcpdclqlsekurlsa_nt6_LsaInitializeProtectedMemory();
VOID kcpdclqlsekurlsa_nt6_LsaCleanupProtectedMemory();
VOID WINAPI kcpdclqlsekurlsa_nt6_LsaUnprotectMemory (IN PVOID Buffer, IN ULONG BufferSize);

NTSTATUS kcpdclqlsekurlsa_nt6_acquireKeys(ULONG_PTR pInitializationVector, ULONG_PTR phAesKey, ULONG_PTR ph3DesKey);
BOOL kcpdclqlsekurlsa_nt6_acquireKey(ULONG_PTR phKey, PJoAA_BCRYPT_GEN_KEY pGenKey);