/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "ydeuclqlldap.h"

BOOL ydeuclqlldap_getLdapAndRootDN(PCWCHAR system, PCWCHAR nc, PLDAP *ld, PWCHAR *rootDn)
{
	BOOL status = FALSE;
	DWORD dwErr;

	if(*ld = ldap_init((PWCHAR) system, LDAP_PORT))
	{
		if(*rootDn = ydeuclqlldap_getRootDomainNamingContext(nc, *ld))
		{
			dwErr = ldap_bind_s(*ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
			status = (dwErr == LDAP_SUCCESS);
			if(!status)
			{
				PRINT_ERROR(L"ldap_bind_s 0x%x (%u)\n", dwErr, dwErr);
				*rootDn = (PWCHAR) LocalFree(*rootDn);
			}
		}
		if(!status)
			ldap_unbind(*ld);
	}
	else PRINT_ERROR(L"ldap_init\n");
	return status;
}

PWCHAR ydeuclqlldap_getRootDomainNamingContext(PCWCHAR nc, LDAP *ld)
{
	DWORD dwErr;
	PWCHAR rootAttr[] = {nc ? (PWCHAR) nc : L"rootDomainNamingContext", NULL}, ret = NULL;
	PLDAPMessage pMessage = NULL;
	PBERVAL *pBerVal;

	dwErr = ldap_search_s(ld, NULL, LDAP_SCOPE_BASE, L"(dn=RootDSE)", rootAttr, FALSE, &pMessage);
	if(dwErr == LDAP_SUCCESS)
	{
		if(ldap_count_entries(ld, pMessage) == 1)
		{
			if(pBerVal = ldap_get_values_len(ld, pMessage, rootAttr[0]))
			{
				if(ldap_count_values_len(pBerVal) == 1)
					ret = ydeuclqlstring_qad_ansi_c_to_unicode(pBerVal[0]->bv_val, pBerVal[0]->bv_len);
				else PRINT_ERROR(L"ldap_get_values_len is NOT 1\n");
				ldap_value_free_len(pBerVal);
			}
		}
		else PRINT_ERROR(L"ldap_count_entries is NOT 1\n");
	}
	else PRINT_ERROR(L"ldap_search_s 0x%x (%u)\n", dwErr, dwErr);
	if(pMessage)
		ldap_msgfree(pMessage);
	return ret;
}