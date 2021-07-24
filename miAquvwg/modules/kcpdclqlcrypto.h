/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kcpd_m.h"
#include "../modules/ydeuclqlcrypto.h"
#include "../modules/ydeuclqlstring.h"
#include "../modules/ydeuclqlfile.h"
#include "../modules/ydeuclqlregistry.h"
#include "sekurlsa/kcpdclqlsekurlsa.h"
#include "crypto/kcpdclqlcrypto_sc.h"
#include "crypto/kcpdclqlcrypto_extractor.h"
#include "crypto/kcpdclqlcrypto_patch.h"
#include "crypto/kcpdclqlcrypto_pki.h"

typedef struct _KUHL_M_CRYPTO_DWORD_TO_DWORD {
	PCWSTR	name;
	DWORD	id;
} KUHL_M_CRYPTO_DWORD_TO_DWORD, *PKUHL_M_CRYPTO_DWORD_TO_DWORD;

typedef struct _KUHL_M_CRYPTO_NAME_TO_REALNAME {
	PCWSTR	name;
	PCWSTR	realname;
} KUHL_M_CRYPTO_NAME_TO_REALNAME, *PKUHL_M_CRYPTO_NAME_TO_REALNAME;

typedef struct _KUHL_M_CRYPTO_CRYPT_KEY_PROV_INFO {
	DWORD offsetContainerName;
	DWORD offsetProvName;
	DWORD dwProvType;
	DWORD dwFlags;
	DWORD cProvParam;
	DWORD offsetRgProvParam;
	DWORD dwKeySpec;
} KUHL_M_CRYPTO_CRYPT_KEY_PROV_INFO, *PKUHL_M_CRYPTO_CRYPT_KEY_PROV_INFO;

typedef struct _KUHL_M_CRYPTO_CERT_PROP {
	DWORD dwPropId;
	DWORD flags; // ?
	DWORD size;
	BYTE data[ANYSIZE_ARRAY];
} KUHL_M_CRYPTO_CERT_PROP, *PKUHL_M_CRYPTO_CERT_PROP;

typedef struct _KUHL_M_CRYPTO_NCRYPT_GROUP_TO_EXPORT {
	PCWSTR pszAlgorithmGroup;
	PCWSTR pszBlobType;
	PCWSTR pszExtension;
	BOOL needPVKHeader;
} KUHL_M_CRYPTO_NCRYPT_GROUP_TO_EXPORT, *PKUHL_M_CRYPTO_NCRYPT_GROUP_TO_EXPORT;

const KUHL_M kcpdclqlcrypto;

NTSTATUS kcpdclqlcrypto_init();
NTSTATUS kcpdclqlcrypto_clean();

NTSTATUS kcpdclqlcrypto_l_providers(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlcrypto_l_stores(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlcrypto_l_certificates(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlcrypto_l_keys(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlcrypto_hash(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlcrypto_system(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlcrypto_c_cert_to_hw(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlcrypto_keyutil(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlcrypto_platforminfo(int argc, wchar_t * argv[]);

BOOL WINAPI kcpdclqlcrypto_l_stores_enumCallback_print(const void *pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved, void *pvArg);
void kcpdclqlcrypto_certificate_descr(PCCERT_CONTEXT pCertContext);

void kcpdclqlcrypto_printKeyInfos(NCRYPT_KEY_HANDLE hCNGKey, HCRYPTKEY hCAPIKey, OPTIONAL HCRYPTPROV hCAPIProv);
void kcpdclqlcrypto_exportRawKeyToFile(LPCVOID data, DWORD size, BOOL isCNG, DWORD dwKeySpec, DWORD dwProviderType, const wchar_t * store, const DWORD index, const wchar_t * name, BOOL wantExport, BOOL wantInfos);
void kcpdclqlcrypto_exportKeyToFile(NCRYPT_KEY_HANDLE hCngKey, HCRYPTKEY hCapiKey, DWORD keySpec, const wchar_t * store, const DWORD index, const wchar_t * name);
void kcpdclqlcrypto_exportCert(PCCERT_CONTEXT pCertificate, BOOL havePrivateKey, const wchar_t * systemStore, const wchar_t * store, const DWORD index, const wchar_t * name);
wchar_t * kcpdclqlcrypto_generateFileName(const wchar_t * term0, const wchar_t * term1, const DWORD index, const wchar_t * name, const wchar_t * ext);
void kcpdclqlcrypto_file_rawData(PKUHL_M_CRYPTO_CERT_PROP prop, PCWCHAR inFile, BOOL isExport);
void kcpdclqlcrypto_l_keys_capi(LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags, BOOL export, LPCWSTR szStore);
void kcpdclqlcrypto_l_keys_cng(LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwFlags, BOOL export, LPCWSTR szStore);

BOOL kcpdclqlcrypto_system_data(PBYTE data, DWORD len, PCWCHAR originalName, BOOL isExport);
BOOL CALLBACK kcpdclqlcrypto_system_directory(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg);