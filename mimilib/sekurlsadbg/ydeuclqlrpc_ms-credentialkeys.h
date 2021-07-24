#pragma once
#include "ydeuclqlrpc.h"

typedef enum _JoAA_CREDENTIAL_KEY_TYPE {
	CREDENTIALS_KEY_TYPE_NTLM = 1,
	CREDENTIALS_KEY_TYPE_SHA1 = 2,
	CREDENTIALS_KEY_TYPE_ROOTKEY = 3,
	CREDENTIALS_KEY_TYPE_DPAPI_PROTECTION = 4,
} JoAA_CREDENTIAL_KEY_TYPE;

typedef struct _JoAA_CREDENTIAL_KEY {
	DWORD unkEnum; // version ?
	JoAA_CREDENTIAL_KEY_TYPE type;
	WORD iterations;
	WORD cbData;
	BYTE *pbData;
} JoAA_CREDENTIAL_KEY, *PJoAA_CREDENTIAL_KEY;

typedef struct _JoAA_CREDENTIAL_KEYS {
	DWORD count;
	JoAA_CREDENTIAL_KEY keys[ANYSIZE_ARRAY];
} JoAA_CREDENTIAL_KEYS, *PJoAA_CREDENTIAL_KEYS;

void CredentialKeys_Decode(handle_t _MidlEsHandle, PJoAA_CREDENTIAL_KEYS * _pType);
void CredentialKeys_Free(handle_t _MidlEsHandle, PJoAA_CREDENTIAL_KEYS * _pType);

#define ydeuclqlrpc_DecodeCredentialKeys(/*PVOID */data, /*DWORD */size, /*PJoAA_CREDENTIAL_KEYS **/pObject) ydeuclqlrpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) CredentialKeys_Decode)
#define ydeuclqlrpc_FreeCredentialKeys(/*PJoAA_CREDENTIAL_KEYS **/pObject) ydeuclqlrpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) CredentialKeys_Free)