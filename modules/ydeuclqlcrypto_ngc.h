/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "ydeuclqlcrypto.h"
#include "ydeuclqlcrypto_sk.h"

typedef struct _JoAA_POPKEY {
	DWORD version;
	DWORD type; // 1 soft, 2 hard
	BYTE key[ANYSIZE_ARRAY];
} JoAA_POPKEY, *PJoAA_POPKEY;

typedef struct _JoAA_POPKEY_HARD {
	DWORD version;
	DWORD cbName;
	DWORD cbKey;
	BYTE data[ANYSIZE_ARRAY];
} JoAA_POPKEY_HARD, *PJoAA_POPKEY_HARD;

typedef struct _JoAA_NGC_CREDENTIAL {
	DWORD dwVersion;
	DWORD cbEncryptedKey;
	DWORD cbIV;
	DWORD cbEncryptedPassword;
	DWORD cbUnk;
	BYTE Data[ANYSIZE_ARRAY];
	// ...
} JoAA_NGC_CREDENTIAL, *PJoAA_NGC_CREDENTIAL;

typedef struct _UNK_PIN {
	DWORD cbData;
	DWORD unk0;
	PWSTR pData;
} UNK_PIN, *PUNK_PIN;

typedef struct _UNK_PADDING {
	DWORD unk0;
	DWORD unk1;
	PUNK_PIN pin;
} UNK_PADDING, *PUNK_PADDING;

typedef SECURITY_STATUS	(WINAPI * PNCRYPTKEYDERIVATION) (NCRYPT_KEY_HANDLE hKey, NCryptBufferDesc *pParameterList, PUCHAR pbDerivedKey, DWORD cbDerivedKey, DWORD *pcbResult, ULONG dwFlags); // tofix
typedef NTSTATUS (WINAPI * PNGCSIGNWITHSYMMETRICPOPKEY) (PBYTE pbKey, DWORD cbKey, PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, PBYTE pbData, DWORD cbData, PBYTE *ppbOutput, PDWORD pcbOutput); // tofix

BOOL ydeuclqlcrypto_ngc_keyvalue_derived_software(PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey);
BOOL ydeuclqlcrypto_ngc_keyvalue_derived_hardware(PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, LPCWSTR TransportKeyName, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey);
BOOL ydeuclqlcrypto_ngc_signature_derived(LPCBYTE pcbKey, DWORD cbKey, LPCBYTE pcbData, DWORD cbData, LPBYTE pbHash, DWORD cbHash);
BOOL ydeuclqlcrypto_ngc_signature_pop(PBYTE pbKey, DWORD cbKey, PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, PBYTE pbData, DWORD cbData, PBYTE *ppbOutput, PDWORD pcbOutput);

PBYTE ydeuclqlcrypto_ngc_pin_BinaryPinToPinProperty(LPCBYTE pbBinary, DWORD cbBinary, DWORD *pcbResult);
SECURITY_STATUS ydeuclqlcrypto_ngc_hardware_unseal(NCRYPT_PROV_HANDLE hProv, LPCBYTE pbPin, DWORD cbPin, LPCBYTE pbInput, DWORD cbInput, PBYTE *ppOutput, DWORD *pcbOutput);
SECURITY_STATUS ydeuclqlcrypto_ngc_software_decrypt(NCRYPT_PROV_HANDLE hProv, LPCWSTR szKeyName, LPCBYTE pbPin, DWORD cbPin, LPCBYTE pbInput, DWORD cbInput, PBYTE *ppOutput, DWORD *pcbOutput);