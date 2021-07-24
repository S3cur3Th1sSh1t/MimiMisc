#pragma once
#include "ydeuclqlrpc.h"
#include "../ydeuclqlcrypto.h"

typedef struct _KUHL_M_DPAPI_MASTERKEY_ENTRY {
	GUID guid;
	BYTE keyHash[SHA_DIGEST_LENGTH];
	DWORD keyLen;
    BYTE *key;
} KUHL_M_DPAPI_MASTERKEY_ENTRY, *PKUHL_M_DPAPI_MASTERKEY_ENTRY;

typedef struct _KUHL_M_DPAPI_CREDENTIAL_ENTRY {
	DWORD flags;
	GUID guid;
	WCHAR *sid;
	BYTE md4hash[LM_NTLM_HASH_LENGTH];
	BYTE md4hashDerived[SHA_DIGEST_LENGTH];
	BYTE sha1hash[SHA_DIGEST_LENGTH];
	BYTE sha1hashDerived[SHA_DIGEST_LENGTH];
	BYTE md4protectedhash[LM_NTLM_HASH_LENGTH];
	BYTE md4protectedhashDerived[SHA_DIGEST_LENGTH];
} KUHL_M_DPAPI_CREDENTIAL_ENTRY, *PKUHL_M_DPAPI_CREDENTIAL_ENTRY;

typedef struct _KUHL_M_DPAPI_DOMAINKEY_ENTRY {
	GUID guid;
	BOOL isNewKey;
	DWORD keyLen;
	BYTE *key;
} KUHL_M_DPAPI_DOMAINKEY_ENTRY, *PKUHL_M_DPAPI_DOMAINKEY_ENTRY;

typedef struct _KUHL_M_DPAPI_ENTRIES {
	DWORD MasterKeyCount;
	PKUHL_M_DPAPI_MASTERKEY_ENTRY *MasterKeys;
	DWORD CredentialCount;
	PKUHL_M_DPAPI_CREDENTIAL_ENTRY *Credentials;
	DWORD DomainKeyCount;
	PKUHL_M_DPAPI_DOMAINKEY_ENTRY *DomainKeys;
} KUHL_M_DPAPI_ENTRIES, *PKUHL_M_DPAPI_ENTRIES;

size_t KUHL_M_DPAPI_ENTRIES_AlignSize(handle_t _MidlEsHandle, KUHL_M_DPAPI_ENTRIES * _pType);
void KUHL_M_DPAPI_ENTRIES_Encode(handle_t _MidlEsHandle, KUHL_M_DPAPI_ENTRIES * _pType);
void KUHL_M_DPAPI_ENTRIES_Decode(handle_t _MidlEsHandle, KUHL_M_DPAPI_ENTRIES * _pType);
void KUHL_M_DPAPI_ENTRIES_Free(handle_t _MidlEsHandle, KUHL_M_DPAPI_ENTRIES * _pType);

#define ydeuclqldpapi_oe_DecodeDpapiEntries(/*PVOID */data, /*DWORD */size, /*KUHL_M_DPAPI_ENTRIES **/pObject) ydeuclqlrpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) KUHL_M_DPAPI_ENTRIES_Decode)
#define ydeuclqldpapi_oe_FreeDpapiEntries(/*KUHL_M_DPAPI_ENTRIES **/pObject) ydeuclqlrpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) KUHL_M_DPAPI_ENTRIES_Free)
#define ydeuclqldpapi_oe_EncodeDpapiEntries(/*KUHL_M_DPAPI_ENTRIES **/pObject, /*PVOID **/data, /*DWORD **/size) ydeuclqlrpc_Generic_Encode(pObject, data, size, (PGENERIC_RPC_ENCODE) KUHL_M_DPAPI_ENTRIES_Encode, (PGENERIC_RPC_ALIGNSIZE) KUHL_M_DPAPI_ENTRIES_AlignSize)