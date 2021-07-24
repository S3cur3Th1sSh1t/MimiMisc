/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <Winldap.h>
#include <WinBer.h>
#include "ydeuclqlstring.h"

BOOL ydeuclqlldap_getLdapAndRootDN(PCWCHAR system, PCWCHAR nc, PLDAP *ld, PWCHAR *rootDn);
PWCHAR ydeuclqlldap_getRootDomainNamingContext(PCWCHAR nc, LDAP *ld);