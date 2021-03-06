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

#define LSA_CREDENTIAL_KEY_PACKAGE_NAME			L"LSACREDKEY"
//#define LSA_CREDENTIAL_KEY_PACKAGE_ID			0x10000				// pseudo package id. must not collide with any other package id	 	
//#define LSA_CREDENTIAL_KEY_NAME					"CredentialKeys" 	
//#define LSA_CREDENTIAL_KEY_ROOT_KEY_ITERATIONS	(1024 * 10)			// in parity with cache logon verifier	 	
//
//typedef enum _LSA_CREDENTIAL_KEY_SOURCE_TYPE {
//	eFromPrecomputed = 1,	// used by Kerberos
//	eFromClearPassword,
//	eFromNtOwf,
//} LSA_CREDENTIAL_KEY_SOURCE_TYPE, *PLSA_CREDENTIAL_KEY_SOURCE_TYPE;
//
//typedef enum _LSA_CREDENTIAL_KEY_TYPE {
//	eDPAPINtOwf = 1,	// legacy NTOWF used by DPAPI
//	eDPAPISha1,			// legacy SHA1 used by DPAPI
//	eRootKey,			// PBKDF2(NTOWF), uplevel root key
//	eDPAPIProtection,	// uplevel DPAPI protection key, derived from root key
//} LSA_CREDENTIAL_KEY_TYPE, *PLSA_CREDENTIAL_KEY_TYPE;
//
//typedef struct _LSA_CREDENTIAL_KEY {
//	LSA_CREDENTIAL_KEY_SOURCE_TYPE SourceType;
//	LSA_CREDENTIAL_KEY_TYPE KeyType;
//	USHORT Iterations;
//	USHORT KeySize;
//#ifdef MIDL_PASS
//	[size_is(KeySize)]
//#endif // MIDL_PASS	 	
//	PUCHAR KeyBuffer;
//} LSA_CREDENTIAL_KEY, *PLSA_CREDENTIAL_KEY;
//
//typedef struct _LSA_CREDENTIAL_KEY_ARRAY {
//	USHORT KeyCount;
//#ifdef MIDL_PASS
//	[size_is(KeyCount)] LSA_CREDENTIAL_KEY Keys[*];
//#else  // MIDL_PASS
//	LSA_CREDENTIAL_KEY Keys[ANYSIZE_ARRAY];
//#endif // MIDL_PASS
//} LSA_CREDENTIAL_KEY_ARRAY, *PLSA_CREDENTIAL_KEY_ARRAY;
//
////
//// convenience helper
////
//typedef struct _LSA_CREDENTIAL_KEY_ARRAY_STORAGE {
//	USHORT KeyCount;
//	LSA_CREDENTIAL_KEY Keys[8];
//} LSA_CREDENTIAL_KEY_ARRAY_STORAGE, *PLSA_CREDENTIAL_KEY_ARRAY_STORAGE;