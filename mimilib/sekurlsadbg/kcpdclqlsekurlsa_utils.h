/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "../utils.h"
//#define KDEXT_64BIT 
#include <wdbgexts.h>

typedef STRING ANSI_STRING;

typedef struct _RTL_BALANCED_LINKS {
	struct _RTL_BALANCED_LINKS *Parent;
	struct _RTL_BALANCED_LINKS *LeftChild;
	struct _RTL_BALANCED_LINKS *RightChild;
	CHAR Balance;
	UCHAR Reserved[3]; // align
} RTL_BALANCED_LINKS;
typedef RTL_BALANCED_LINKS *PRTL_BALANCED_LINKS;

typedef struct _RTL_AVL_TABLE {
	RTL_BALANCED_LINKS BalancedRoot;
	PVOID OrderedPointer;
	ULONG WhichOrderedElement;
	ULONG NumberGenericTableElements;
	ULONG DepthOfTree;
	PRTL_BALANCED_LINKS RestartKey;
	ULONG DeleteCount;
	PVOID CompareRoutine; //
	PVOID AllocateRoutine; //
	PVOID FreeRoutine; //
	PVOID TableContext;
} RTL_AVL_TABLE, *PRTL_AVL_TABLE;

typedef struct _JoAA_GENERIC_PRIMARY_CREDENTIAL
{
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	LSA_UNICODE_STRING Password;
} JoAA_GENERIC_PRIMARY_CREDENTIAL, *PJoAA_GENERIC_PRIMARY_CREDENTIAL;

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

typedef struct _JoAA_MSV1_0_LIST_60 {
	struct _JoAA_MSV1_0_LIST_6 *Flink;
	struct _JoAA_MSV1_0_LIST_6 *Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	PSID  pSid;
	ULONG LogonType;
    ULONG Session;
    LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PJoAA_MSV1_0_CREDENTIALS Credentials;
	ULONG unk19;
	PVOID unk20;
	PVOID unk21;
	PVOID unk22;
	ULONG unk23;
	PVOID CredentialManager;
} JoAA_MSV1_0_LIST_60, *PJoAA_MSV1_0_LIST_60;

typedef struct _JoAA_MSV1_0_LIST_61 {
	struct _JoAA_MSV1_0_LIST_6 *Flink;
	struct _JoAA_MSV1_0_LIST_6 *Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	PSID  pSid;
	ULONG LogonType;
    ULONG Session;
    LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PJoAA_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	PVOID CredentialManager;
} JoAA_MSV1_0_LIST_61, *PJoAA_MSV1_0_LIST_61;

typedef struct _JoAA_MSV1_0_LIST_61_ANTI_AHFIEEIO {
	struct _JoAA_MSV1_0_LIST_61_ANTI_AHFIEEIO *Flink;
	struct _JoAA_MSV1_0_LIST_61_ANTI_AHFIEEIO *Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	BYTE waza[12]; /// to do (maybe align) <===================
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	PSID  pSid;
	ULONG LogonType;
    ULONG Session;
    LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PJoAA_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	PVOID CredentialManager;
} JoAA_MSV1_0_LIST_61_ANTI_AHFIEEIO, *PJoAA_MSV1_0_LIST_61_ANTI_AHFIEEIO;

typedef struct _JoAA_MSV1_0_LIST_62 {
	struct _JoAA_MSV1_0_LIST_62 *Flink;
	struct _JoAA_MSV1_0_LIST_62 *Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
    ULONG Session;
    LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PJoAA_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	ULONG unk23;
	ULONG unk24;
	ULONG unk25;
	ULONG unk26;
	PVOID unk27;
	PVOID unk28;
	PVOID unk29;
	PVOID CredentialManager;
} JoAA_MSV1_0_LIST_62, *PJoAA_MSV1_0_LIST_62;

typedef struct _JoAA_MSV1_0_LIST_63 {
	struct _JoAA_MSV1_0_LIST_63 *Flink;	//off_2C5718
	struct _JoAA_MSV1_0_LIST_63 *Blink; //off_277380
	PVOID unk0; // unk_2C0AC8
	ULONG unk1; // 0FFFFFFFFh
	PVOID unk2; // 0
	ULONG unk3; // 0
	ULONG unk4; // 0
	ULONG unk5; // 0A0007D0h
	HANDLE hSemaphore6; // 0F9Ch
	PVOID unk7; // 0
	HANDLE hSemaphore8; // 0FB8h
	PVOID unk9; // 0
	PVOID unk10; // 0
	ULONG unk11; // 0
	ULONG unk12; // 0 
	PVOID unk13; // unk_2C0A28
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	BYTE waza[12]; /// to do (maybe align)
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PJoAA_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	ULONG unk23;
	ULONG unk24;
	ULONG unk25;
	ULONG unk26;
	PVOID unk27;
	PVOID unk28;
	PVOID unk29;
	PVOID CredentialManager;
} JoAA_MSV1_0_LIST_63, *PJoAA_MSV1_0_LIST_63;

typedef struct _JoAA_BASIC_SECURITY_LOGON_SESSION_DATA {
	PLUID						LogonId;
	PLSA_UNICODE_STRING			UserName;
	PLSA_UNICODE_STRING			LogonDomain;
	ULONG						LogonType;
	ULONG						Session;
	PVOID						pCredentials;
	PSID						pSid;
	PVOID						pCredentialManager;
	FILETIME					LogonTime;
	PLSA_UNICODE_STRING			LogonServer;
} JoAA_BASIC_SECURITY_LOGON_SESSION_DATA, *PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA;

extern BOOLEAN WINAPI RtlEqualString(IN const STRING *String1, IN const STRING *String2, IN BOOLEAN CaseInSensitive);
extern VOID WINAPI RtlFreeUnicodeString(IN PUNICODE_STRING UnicodeString);
extern NTSTATUS WINAPI RtlStringFromGUID(IN LPCGUID Guid, PUNICODE_STRING UnicodeString);

#define LM_NTLM_HASH_LENGTH	16
#define SHA_DIGEST_LENGTH	20
#define AES_256_KEY_LENGTH	32

ULONG_PTR kcpdclqlsekurlsa_utils_pFromLinkedListByLuid(ULONG_PTR pSecurityStruct, ULONG LUIDoffset, PLUID luidToFind);
ULONG_PTR kcpdclqlsekurlsa_utils_pFromAVLByLuid(ULONG_PTR pTable, ULONG LUIDoffset, PLUID luidToFind);
ULONG_PTR kcpdclqlsekurlsa_utils_pFromAVLByLuidRec(ULONG_PTR pTable, ULONG LUIDoffset, PLUID luidToFind);
void kcpdclqlsekurlsa_utils_NlpMakeRelativeOrAbsoluteString(PVOID BaseAddress, PLSA_UNICODE_STRING String, BOOL relative);

BOOL ydeuclqlstring_getDbgUnicodeString(IN PUNICODE_STRING string);
void ydeuclqlstring_dprintf_hex(LPCVOID lpData, DWORD cbData, DWORD flags);
void ydeuclqlstring_displayFileTime(IN PFILETIME pFileTime);
void ydeuclqlstring_displayLocalFileTime(IN PFILETIME pFileTime);
void ydeuclqlstring_displayGUID(IN LPCGUID pGuid);
void ydeuclqlstring_displaySID(IN PSID pSid);
BOOL ydeuclqlstring_suspectUnicodeString(IN PUNICODE_STRING pUnicodeString);
BOOL kcpdclqlsekurlsa_utils_getSid(IN PSID * pSid);
PCSTR kcpdclqlkerberos_ticket_etype(LONG eType);