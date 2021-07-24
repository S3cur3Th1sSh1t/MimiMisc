/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "ydeuclqlhandle.h"
#include <sddl.h>

extern NTSTATUS NTAPI NtCompareTokens(IN HANDLE FirstTokenHandle, IN HANDLE SecondTokenHandle, OUT PBOOLEAN Equal);

typedef BOOL (CALLBACK * PKULL_M_TOKEN_ENUM_CALLBACK) (HANDLE hToken, DWORD ptid, PVOID pvArg);

typedef struct _KULL_M_TOKEN_ENUM_DATA {
	PKULL_M_TOKEN_ENUM_CALLBACK callback;
	PVOID pvArg;
	BOOL mustContinue;
} KULL_M_TOKEN_ENUM_DATA, *PKULL_M_TOKEN_ENUM_DATA;

typedef struct _KULL_M_TOKEN_LIST {
	HANDLE hToken;
	DWORD ptid;
	struct _KULL_M_TOKEN_LIST *next;
} KULL_M_TOKEN_LIST, *PKULL_M_TOKEN_LIST;

BOOL ydeuclqltoken_getTokens(PKULL_M_TOKEN_ENUM_CALLBACK callBack, PVOID pvArg);
BOOL ydeuclqltoken_getTokensUnique(PKULL_M_TOKEN_ENUM_CALLBACK callBack, PVOID pvArg);
BOOL CALLBACK ydeuclqltoken_getTokensUnique_callback(HANDLE hToken, DWORD ptid, PVOID pvArg);
BOOL CALLBACK ydeuclqltoken_getTokens_process_callback(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
BOOL CALLBACK ydeuclqltoken_getTokens_handles_callback(HANDLE handle, PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);

BOOL ydeuclqltoken_getNameDomainFromToken(HANDLE hToken, PWSTR * pName, PWSTR * pDomain, PWSTR * pSid, PSID_NAME_USE pSidNameUse);
BOOL ydeuclqltoken_CheckTokenMembership(__in_opt HANDLE TokenHandle, __in PSID SidToCheck, __out PBOOL IsMember);
PCWCHAR ydeuclqltoken_getSidNameUse(SID_NAME_USE SidNameUse);
BOOL ydeuclqltoken_getNameDomainFromSID(PSID pSid, PWSTR * pName, PWSTR * pDomain, PSID_NAME_USE pSidNameUse, LPCWSTR system);
BOOL ydeuclqltoken_getSidDomainFromName(PCWSTR pName, PSID * pSid, PWSTR * pDomain, PSID_NAME_USE pSidNameUse, LPCWSTR system);

BOOL ydeuclqltoken_equal(IN HANDLE First, IN HANDLE Second);
PTOKEN_USER ydeuclqltoken_getUserFromToken(HANDLE hToken);
PWSTR ydeuclqltoken_getSidFromToken(HANDLE hToken);
PWSTR ydeuclqltoken_getCurrentSid();
BOOL ydeuclqltoken_isLocalAccount(__in_opt HANDLE TokenHandle, __out PBOOL IsMember);