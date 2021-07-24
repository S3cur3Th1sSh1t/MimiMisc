/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kcpd_m.h"
#include "../modules/ydeuclqltoken.h"
#include "../modules/ydeuclqlnet.h"
#include "kcpdclqlprocess.h"

const KUHL_M kcpdclqltoken;

//typedef enum _KUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER {
//	TypeFree,
//	TypeAnonymous,
//	TypeIdentity,
//	TypeDelegation,
//	TypeImpersonate,
//	TypePrimary,
//} KUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER, *PKUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER;

typedef struct _KUHL_M_TOKEN_ELEVATE_DATA {
	PSID pSid;
	PCWSTR pUsername;
	DWORD tokenId;
	BOOL elevateIt;
	BOOL runIt;
	PCWSTR pCommandLine;
	BOOL isSidDirectUser;

	//KUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER filter;
	//BOOL isNeeded;
	//BOOL isMinimal;
} KUHL_M_TOKEN_ELEVATE_DATA, *PKUHL_M_TOKEN_ELEVATE_DATA;

void kcpdclqltoken_displayAccount_sids(UCHAR l, DWORD count, PSID_AND_ATTRIBUTES sids);
void kcpdclqltoken_displayAccount(HANDLE hToken, BOOL full);

NTSTATUS kcpdclqltoken_whoami(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqltoken_list(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqltoken_elevate(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqltoken_run(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqltoken_revert(int argc, wchar_t * argv[]);

NTSTATUS kcpdclqltoken_list_or_elevate(int argc, wchar_t * argv[], BOOL elevate, BOOL runIt);
BOOL CALLBACK kcpdclqltoken_list_or_elevate_callback(HANDLE hToken, DWORD ptid, PVOID pvArg);