/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kwindbg.h"
#include "ydeuclqlrpc_ms-credentialkeys.h"

void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_msv(IN ULONG_PTR reserved, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_kerberos(IN ULONG_PTR pKerbGlobalLogonSessionTable, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_livessp(IN ULONG_PTR pLiveGlobalLogonSessionList, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_tspkg(IN ULONG_PTR pTSGlobalCredTable, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_wdigest(IN ULONG_PTR pl_LogSessList, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_ssp(IN ULONG_PTR pSspCredentialList, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_masterkeys(IN ULONG_PTR pMasterKeyCacheList, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_credman(IN ULONG_PTR reserved, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _MSV1_0_PRIMARY_CREDENTIAL { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName; 
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL, *PMSV1_0_PRIMARY_CREDENTIAL;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10_OLD { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	BYTE align0;
	BYTE align1;
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_10_OLD, *PMSV1_0_PRIMARY_CREDENTIAL_10_OLD;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10 { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	BYTE align0;
	BYTE align1;
	BYTE align2;
	BYTE align3;
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_10, *PMSV1_0_PRIMARY_CREDENTIAL_10;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10_1607 { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	PVOID pNtlmCredIsoInProc;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	BOOLEAN isDPAPIProtected;
	BYTE align0;
	BYTE align1;
	BYTE align2;
	DWORD unkD; // 1/2
	#pragma pack(push, 2)
	WORD isoSize;  // 0000
	BYTE DPAPIProtected[LM_NTLM_HASH_LENGTH];
	DWORD align3; // 00000000
	#pragma pack(pop) 
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_10_1607, *PMSV1_0_PRIMARY_CREDENTIAL_10_1607;

typedef struct _MSV1_0_PRIMARY_HELPER {
	LONG offsetToLogonDomain;
	LONG offsetToUserName;
	LONG offsetToisIso;
	LONG offsetToisNtOwfPassword;
	LONG offsetToisLmOwfPassword;
	LONG offsetToisShaOwPassword;
	LONG offsetToisDPAPIProtected;
	LONG offsetToNtOwfPassword;
	LONG offsetToLmOwfPassword;
	LONG offsetToShaOwPassword;
	LONG offsetToDPAPIProtected;
	LONG offsetToIso;
} MSV1_0_PRIMARY_HELPER, *PMSV1_0_PRIMARY_HELPER;

const MSV1_0_PRIMARY_HELPER * kcpdclqlsekurlsa_msv_helper();

typedef struct _KERB_HASHPASSWORD_GENERIC {
	DWORD Type;
	SIZE_T Size;
	PBYTE Checksump;
} KERB_HASHPASSWORD_GENERIC, *PKERB_HASHPASSWORD_GENERIC;

typedef struct _KERB_HASHPASSWORD_6 {
	LSA_UNICODE_STRING salt;	// http://tools.ietf.org/html/rfc3962
	PVOID stringToKey; // AES Iterations (dword ?)
	KERB_HASHPASSWORD_GENERIC generic;
} KERB_HASHPASSWORD_6, *PKERB_HASHPASSWORD_6;

typedef struct _KERB_HASHPASSWORD_6_1607 {
	LSA_UNICODE_STRING salt;	// http://tools.ietf.org/html/rfc3962
	PVOID stringToKey; // AES Iterations (dword ?)
	PVOID unk0;
	KERB_HASHPASSWORD_GENERIC generic;
} KERB_HASHPASSWORD_6_1607, *PKERB_HASHPASSWORD_6_1607;

typedef struct _JoAA_KERBEROS_KEYS_LIST_6 {
	DWORD unk0;		// dword_1233EC8 dd 4
	DWORD cbItem;	// debug048:01233ECC dd 5
	PVOID unk1;
	PVOID unk2;
	PVOID unk3;
	PVOID unk4;
	//KERB_HASHPASSWORD_6 KeysEntries[ANYSIZE_ARRAY];
} JoAA_KERBEROS_KEYS_LIST_6, *PJoAA_KERBEROS_KEYS_LIST_6;

typedef struct _KERB_SMARTCARD_CSP_INFO {
	DWORD dwCspInfoLen;
	DWORD MessageType;
	union {
		PVOID   ContextInformation;
		ULONG64 SpaceHolderForWow64;
	};
	DWORD flags;
	DWORD KeySpec;
	ULONG nCardNameOffset;
	ULONG nReaderNameOffset;
	ULONG nContainerNameOffset;
	ULONG nCSPNameOffset;
	WCHAR bBuffer[ANYSIZE_ARRAY];
} KERB_SMARTCARD_CSP_INFO, *PKERB_SMARTCARD_CSP_INFO;

typedef struct _JoAA_KERBEROS_CSP_INFOS_60 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;

	PVOID unkData;	// 0 = CspData
	DWORD Flags;	// 0 = CspData
	DWORD unkFlags;	// 0x141

	DWORD CspDataLength;
	KERB_SMARTCARD_CSP_INFO CspData;
} JoAA_KERBEROS_CSP_INFOS_60, *PJoAA_KERBEROS_CSP_INFOS_60;

typedef struct _JoAA_KERBEROS_CSP_INFOS_62 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;
	PVOID unk2;
	PVOID unkData;	// 0 = CspData
	DWORD Flags;	// 0 = CspData
	DWORD unkFlags;	// 0x141 (not 0x61)

	DWORD CspDataLength;
	KERB_SMARTCARD_CSP_INFO CspData;
} JoAA_KERBEROS_CSP_INFOS_62, *PJoAA_KERBEROS_CSP_INFOS_62;

typedef struct _JoAA_KERBEROS_CSP_INFOS_10 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;
	PVOID unk2;
	PVOID unkData;	// 0 = CspData
	DWORD Flags;	// 0 = CspData
	DWORD unkFlags;	// 0x141 (not 0x61)
	PVOID unk3;
	DWORD CspDataLength;
	KERB_SMARTCARD_CSP_INFO CspData;
} JoAA_KERBEROS_CSP_INFOS_10, *PJoAA_KERBEROS_CSP_INFOS_10;

typedef struct _JoAA_KERBEROS_LOGON_SESSION {
	ULONG		UsageCount;
	LIST_ENTRY	unk0;
	PVOID		unk1;
	ULONG		unk2;	// filetime.1 ?
	ULONG		unk3;	// filetime.2 ?
	PVOID		unk4;
	PVOID		unk5;
	PVOID		unk6;
	LUID		LocallyUniqueIdentifier;
#if defined(_M_IX86)
	ULONG		unkAlign;
#endif
	FILETIME	unk7;
	PVOID		unk8;
	ULONG		unk9;	// filetime.1 ?
	ULONG		unk10;	// filetime.2 ?
	PVOID		unk11;
	PVOID		unk12;
	PVOID		unk13;
	JoAA_GENERIC_PRIMARY_CREDENTIAL	credentials;
	ULONG		unk14;
	ULONG		unk15;
	ULONG		unk16;
	ULONG		unk17;
	PVOID		unk18;
	PVOID		unk19;
	PVOID		unk20;
	PVOID		unk21;
	PVOID		pKeyList;
	PVOID		unk23;
	LIST_ENTRY	Tickets_1;
	FILETIME	unk24;
	LIST_ENTRY	Tickets_2;
	FILETIME	unk25;
	LIST_ENTRY	Tickets_3;
	FILETIME	unk26;
	PVOID		SmartcardInfos;
} JoAA_KERBEROS_LOGON_SESSION, *PJoAA_KERBEROS_LOGON_SESSION;

typedef struct _JoAA_KERBEROS_10_PRIMARY_CREDENTIAL
{
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID		unk0;
	LSA_UNICODE_STRING Password;
} JoAA_KERBEROS_10_PRIMARY_CREDENTIAL, *PJoAA_KERBEROS_10_PRIMARY_CREDENTIAL;

typedef struct _JoAA_KERBEROS_LOGON_SESSION_10 {
	ULONG		UsageCount;
	LIST_ENTRY	unk0;
	PVOID		unk1;
	ULONG		unk1b;
	FILETIME	unk2;
	PVOID		unk4;
	PVOID		unk5;
	PVOID		unk6;
	LUID		LocallyUniqueIdentifier;
	FILETIME	unk7;
	PVOID		unk8;
	ULONG		unk8b;
	FILETIME	unk9;
	PVOID		unk11;
	PVOID		unk12;
	PVOID		unk13;
#if defined(_M_IX86)
	ULONG		unkAlign;
#endif
	JoAA_KERBEROS_10_PRIMARY_CREDENTIAL	credentials;
	ULONG		unk14;
	ULONG		unk15;
	ULONG		unk16;
	ULONG		unk17;
	//PVOID		unk18;
	PVOID		unk19;
	PVOID		unk20;
	PVOID		unk21;
	PVOID		unk22;
	PVOID		unk23;
	PVOID		unk24;
	PVOID		unk25;
	PVOID		pKeyList;
	PVOID		unk26;
	LIST_ENTRY	Tickets_1;
	FILETIME	unk27;
	LIST_ENTRY	Tickets_2;
	FILETIME	unk28;
	LIST_ENTRY	Tickets_3;
	FILETIME	unk29;
	PVOID		SmartcardInfos;
} JoAA_KERBEROS_LOGON_SESSION_10, *PJoAA_KERBEROS_LOGON_SESSION_10;

typedef struct _JoAA_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO
{
	DWORD StructSize;
	struct _LSAISO_DATA_BLOB *isoBlob; // aligned;
} JoAA_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO, *PJoAA_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO;

typedef struct _JoAA_KERBEROS_10_PRIMARY_CREDENTIAL_1607
{
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID		unkFunction;
	DWORD		type; // or flags 2 = normal, 1 = ISO
	union {
		LSA_UNICODE_STRING Password;
		JoAA_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO IsoPassword;
	};
} JoAA_KERBEROS_10_PRIMARY_CREDENTIAL_1607, *PJoAA_KERBEROS_10_PRIMARY_CREDENTIAL_1607;

typedef struct _JoAA_KERBEROS_LOGON_SESSION_10_1607 {
	ULONG		UsageCount;
	LIST_ENTRY	unk0;
	PVOID		unk1;
	ULONG		unk1b;
	FILETIME	unk2;
	PVOID		unk4;
	PVOID		unk5;
	PVOID		unk6;
	LUID		LocallyUniqueIdentifier;
	FILETIME	unk7;
	PVOID		unk8;
	ULONG		unk8b;
	FILETIME	unk9;
	PVOID		unk11;
	PVOID		unk12;
	PVOID		unk13;
#if defined(_M_IX86)
	ULONG		unkAlign;
#endif
	JoAA_KERBEROS_10_PRIMARY_CREDENTIAL_1607	credentials;
	ULONG		unk14;
	ULONG		unk15;
	ULONG		unk16;
	ULONG		unk17;
	PVOID		unk18;
	PVOID		unk19;
	PVOID		unk20;
	PVOID		unk21;
	PVOID		unk22;
	PVOID		unk23;
	PVOID		unk24;
	PVOID		unk25;
	PVOID		pKeyList;
	PVOID		unk26;
	LIST_ENTRY	Tickets_1;
	FILETIME	unk27;
	LIST_ENTRY	Tickets_2;
	FILETIME	unk28;
	LIST_ENTRY	Tickets_3;
	FILETIME	unk29;
	PVOID		SmartcardInfos;
} JoAA_KERBEROS_LOGON_SESSION_10_1607, *PJoAA_KERBEROS_LOGON_SESSION_10_1607;

typedef struct _KERB_INFOS {
	LONG	offsetLuid;
	LONG	offsetCreds;
	LONG	offsetPin;
	LONG	offsetKeyList;
	LONG	offsetHashGeneric;
	SIZE_T	structKeyPasswordHashSize;
	SIZE_T	structSize;
	LONG	offsetSizeOfCsp;
	LONG	offsetNames;
	SIZE_T	structCspInfosSize;
} KERB_INFOS, *PKERB_INFOS;

typedef struct _JoAA_LIVESSP_PRIMARY_CREDENTIAL
{
	ULONG isSupp;
	ULONG unk0;
	JoAA_GENERIC_PRIMARY_CREDENTIAL credentials;
} JoAA_LIVESSP_PRIMARY_CREDENTIAL, *PJoAA_LIVESSP_PRIMARY_CREDENTIAL;

typedef struct _JoAA_LIVESSP_LIST_ENTRY
{
	struct _JoAA_LIVESSP_LIST_ENTRY *Flink;
	struct _JoAA_LIVESSP_LIST_ENTRY *Blink;
	PVOID	unk0;
	PVOID	unk1;
	PVOID	unk2;
	PVOID	unk3;
	DWORD	unk4;
	DWORD	unk5;
	PVOID	unk6;
	LUID	LocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	PVOID	unk7;
	PJoAA_LIVESSP_PRIMARY_CREDENTIAL suppCreds;
} JoAA_LIVESSP_LIST_ENTRY, *PJoAA_LIVESSP_LIST_ENTRY;

typedef struct _JoAA_TS_PRIMARY_CREDENTIAL {
	PVOID unk0;	// lock ?
	JoAA_GENERIC_PRIMARY_CREDENTIAL credentials;
} JoAA_TS_PRIMARY_CREDENTIAL, *PJoAA_TS_PRIMARY_CREDENTIAL;

typedef struct _JoAA_TS_CREDENTIAL {
#if defined(_M_X64) || defined(_M_ARM64)
	BYTE unk0[108];
#elif defined(_M_IX86)
	BYTE unk0[64];
#endif
	LUID LocallyUniqueIdentifier;
	PVOID unk1;
	PVOID unk2;
	PJoAA_TS_PRIMARY_CREDENTIAL pTsPrimary;
} JoAA_TS_CREDENTIAL, *PJoAA_TS_CREDENTIAL;

typedef struct _JoAA_TS_CREDENTIAL_1607 {
#if defined(_M_X64) || defined(_M_ARM64)
	BYTE unk0[112];
#elif defined(_M_IX86)
	BYTE unk0[68];
#endif
	LUID LocallyUniqueIdentifier;
	PVOID unk1;
	PVOID unk2;
	PJoAA_TS_PRIMARY_CREDENTIAL pTsPrimary;
} JoAA_TS_CREDENTIAL_1607, *PJoAA_TS_CREDENTIAL_1607;

typedef struct _JoAA_TS_CREDENTIAL_HELPER {
	LONG offsetToLuid;
	LONG offsetToTsPrimary;
} JoAA_TS_CREDENTIAL_HELPER, *PJoAA_TS_CREDENTIAL_HELPER;

#if defined(_M_X64) || defined(_M_ARM64)
	#define offsetWDigestPrimary 48
#elif defined(_M_IX86)
	#define offsetWDigestPrimary 32
#endif
typedef struct _JoAA_WDIGEST_LIST_ENTRY {
	struct _JoAA_WDIGEST_LIST_ENTRY *Flink;
	struct _JoAA_WDIGEST_LIST_ENTRY *Blink;
	ULONG	UsageCount;
	struct _JoAA_WDIGEST_LIST_ENTRY *This;
	LUID LocallyUniqueIdentifier;
} JoAA_WDIGEST_LIST_ENTRY, *PJoAA_WDIGEST_LIST_ENTRY;

typedef struct _JoAA_SSP_CREDENTIAL_LIST_ENTRY {
	struct _JoAA_SSP_CREDENTIAL_LIST_ENTRY *Flink;
	struct _JoAA_SSP_CREDENTIAL_LIST_ENTRY *Blink;
	ULONG References;
	ULONG CredentialReferences;
	LUID LogonId;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	JoAA_GENERIC_PRIMARY_CREDENTIAL credentials;
} JoAA_SSP_CREDENTIAL_LIST_ENTRY, *PJoAA_SSP_CREDENTIAL_LIST_ENTRY;

typedef struct _JoAA_MASTERKEY_CACHE_ENTRY {
	struct _JoAA_MATERKEY_CACHE_ENTRY *Flink;
	struct _JoAA_MATERKEY_CACHE_ENTRY *Blink;
	LUID LogonId;
	GUID KeyUid;
	FILETIME insertTime;
	ULONG keySize;
	BYTE  key[ANYSIZE_ARRAY];
} JoAA_MASTERKEY_CACHE_ENTRY, *PJoAA_MASTERKEY_CACHE_ENTRY;

typedef struct _CREDMAN_INFOS {
	ULONG	structSize;
	ULONG	offsetFLink;
	ULONG	offsetUsername;
	ULONG	offsetDomain;
	ULONG	offsetCbPassword;
	ULONG	offsetPassword;
} CREDMAN_INFOS, *PCREDMAN_INFOS;

typedef struct _JoAA_CREDMAN_LIST_ENTRY_60 {
	ULONG cbEncPassword;
	PWSTR encPassword;
	ULONG unk0;
	ULONG unk1;
	PVOID unk2;
	PVOID unk3;
	PWSTR UserName;
	ULONG cbUserName;
	struct _JoAA_CREDMAN_LIST_ENTRY *Flink;
	struct _JoAA_CREDMAN_LIST_ENTRY *Blink;
	UNICODE_STRING type;
	PVOID unk5;
	UNICODE_STRING server1;
	PVOID unk6;
	PVOID unk7;
	PVOID unk8;
	PVOID unk9;
	PVOID unk10;
	UNICODE_STRING user;
	ULONG unk11;
	UNICODE_STRING server2;
} JoAA_CREDMAN_LIST_ENTRY_60, *PJoAA_CREDMAN_LIST_ENTRY_60;

typedef struct _JoAA_CREDMAN_LIST_ENTRY {
	ULONG cbEncPassword;
	PWSTR encPassword;
	ULONG unk0;
	ULONG unk1;
	PVOID unk2;
	PVOID unk3;
	PWSTR UserName;
	ULONG cbUserName;
	struct _JoAA_CREDMAN_LIST_ENTRY *Flink;
	struct _JoAA_CREDMAN_LIST_ENTRY *Blink;
	LIST_ENTRY unk4;
	UNICODE_STRING type;
	PVOID unk5;
	UNICODE_STRING server1;
	PVOID unk6;
	PVOID unk7;
	PVOID unk8;
	PVOID unk9;
	PVOID unk10;
	UNICODE_STRING user;
	ULONG unk11;
	UNICODE_STRING server2;
} JoAA_CREDMAN_LIST_ENTRY, *PJoAA_CREDMAN_LIST_ENTRY;

typedef struct _JoAA_CREDMAN_LIST_STARTER {
	ULONG unk0;
	PJoAA_CREDMAN_LIST_ENTRY start;
	//...
} JoAA_CREDMAN_LIST_STARTER, *PJoAA_CREDMAN_LIST_STARTER;

typedef struct _JoAA_CREDMAN_SET_LIST_ENTRY {
	struct _JoAA_CREDMAN_SET_LIST_ENTRY *Flink;
	struct _JoAA_CREDMAN_SET_LIST_ENTRY *Blink;
	ULONG unk0;
	PJoAA_CREDMAN_LIST_STARTER list1;
	PJoAA_CREDMAN_LIST_STARTER list2;
	// ...
} JoAA_CREDMAN_SET_LIST_ENTRY, *PJoAA_CREDMAN_SET_LIST_ENTRY;

typedef struct _JoAA_KRBTGT_CREDENTIAL_64 {
	PVOID unk0;
	PVOID unk1_key_salt;
	PVOID flags;
	PVOID unk2; //
	PVOID type;
	PVOID size;
	PVOID key;
} JoAA_KRBTGT_CREDENTIAL_64, *PJoAA_KRBTGT_CREDENTIAL_64;

typedef struct _JoAA_KRBTGT_CREDENTIALS_64 {
	DWORD unk0_ver;
	DWORD cbCred;
	PVOID unk1;
	LSA_UNICODE_STRING salt;
	PVOID unk2;
	JoAA_KRBTGT_CREDENTIAL_64 credentials[ANYSIZE_ARRAY];
} JoAA_KRBTGT_CREDENTIALS_64, *PJoAA_KRBTGT_CREDENTIALS_64;

typedef struct _JoAA_KRBTGT_CREDENTIAL_6 {
	PVOID unk0;
	PVOID unk1_key_salt;
	PVOID flags;
	PVOID type;
	PVOID size;
	PVOID key;
} JoAA_KRBTGT_CREDENTIAL_6, *PJoAA_KRBTGT_CREDENTIAL_6;

typedef struct _JoAA_KRBTGT_CREDENTIALS_6 {
	DWORD unk0_ver;
	DWORD cbCred;
	PVOID unk1;
	LSA_UNICODE_STRING salt;
	PVOID unk2;
	JoAA_KRBTGT_CREDENTIAL_6 credentials[ANYSIZE_ARRAY];
} JoAA_KRBTGT_CREDENTIALS_6, *PJoAA_KRBTGT_CREDENTIALS_6;

typedef struct _DUAL_KRBTGT {
	PVOID krbtgt_current;
	PVOID krbtgt_previous;
} DUAL_KRBTGT, *PDUAL_KRBTGT;

typedef struct _KDC_DOMAIN_KEY {
	LONG	type;
	DWORD	size;
	DWORD	offset;
} KDC_DOMAIN_KEY, *PKDC_DOMAIN_KEY;

typedef struct _KDC_DOMAIN_KEYS {
	DWORD		keysSize; //60
	DWORD		unk0;
	DWORD		nbKeys;
	KDC_DOMAIN_KEY keys[ANYSIZE_ARRAY];
} KDC_DOMAIN_KEYS, *PKDC_DOMAIN_KEYS;

typedef struct _KDC_DOMAIN_KEYS_INFO {
	PKDC_DOMAIN_KEYS	keys;
	DWORD				keysSize; //60
	LSA_UNICODE_STRING	password;
} KDC_DOMAIN_KEYS_INFO, *PKDC_DOMAIN_KEYS_INFO;

typedef struct _KDC_DOMAIN_INFO {
	LIST_ENTRY list;
	LSA_UNICODE_STRING	FullDomainName;
	LSA_UNICODE_STRING	NetBiosName;
	PVOID		current;
	DWORD		unk1;	// 4		// 0
	DWORD		unk2;	// 8		// 32
	DWORD		unk3;	// 2		// 0
	DWORD		unk4;	// 1		// 1
	PVOID		unk5;	// 8*0
	DWORD		unk6;	// 3		// 2
	// align
	PSID		DomainSid;
	KDC_DOMAIN_KEYS_INFO	IncomingAuthenticationKeys;
	KDC_DOMAIN_KEYS_INFO	OutgoingAuthenticationKeys;
	KDC_DOMAIN_KEYS_INFO	IncomingPreviousAuthenticationKeys;
	KDC_DOMAIN_KEYS_INFO	OutgoingPreviousAuthenticationKeys;
} KDC_DOMAIN_INFO , *PKDC_DOMAIN_INFO;

typedef struct _LSAISO_DATA_BLOB {
	DWORD structSize;
	DWORD unk0;
	DWORD typeSize;
	DWORD unk1;
	DWORD unk2;
	DWORD unk3;
	DWORD unk4;
	BYTE unkKeyData[3*16];
	BYTE unkData2[16];
	DWORD unk5;
	DWORD origSize;
	BYTE data[ANYSIZE_ARRAY];
} LSAISO_DATA_BLOB, *PLSAISO_DATA_BLOB;

typedef struct _ENC_LSAISO_DATA_BLOB {
	BYTE unkData1[16];
	BYTE unkData2[16];
	BYTE data[ANYSIZE_ARRAY];
} ENC_LSAISO_DATA_BLOB, *PENC_LSAISO_DATA_BLOB;

typedef struct _JoAA_BACKUP_KEY {
	DWORD version;
	DWORD keyLen;
	DWORD certLen;
	BYTE data[ANYSIZE_ARRAY];
} JoAA_BACKUP_KEY, *PJoAA_BACKUP_KEY;