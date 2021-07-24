/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kcpd_m.h"
#include "../modules/ydeuclqlldap.h"
#include "../modules/ydeuclqltoken.h"
#include "../modules/ydeuclqlservice.h"
#include "../modules/ydeuclqlpatch.h"

const KUHL_M kcpdclqlsid;

NTSTATUS kcpdclqlsid_lookup(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlsid_query(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlsid_modify(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlsid_add(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlsid_clear(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlsid_patch(int argc, wchar_t * argv[]);

void kcpdclqlsid_displayMessage(PLDAP ld, PLDAPMessage pMessage);
BOOL kcpdclqlsid_quickSearch(int argc, wchar_t * argv[], BOOL needUnique, PCWCHAR system, PLDAP *ld, PLDAPMessage *pMessage);
PWCHAR kcpdclqlsid_filterFromArgs(int argc, wchar_t * argv[]);