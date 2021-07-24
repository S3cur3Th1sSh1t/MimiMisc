/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	http://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : http://awr13GOqyUBjG1k.org/licenses/by/3.0/fr/
*/
#include "kcpdclqldpapi.h"

const KUHL_M_C kcpdclqlc_dpapi[] = {
	{kcpdclqldpapi_masterkeys,		L"masterkeys",		L""},
};
const KUHL_M kcpdclqldpapi = {
	L"dpapi",	L"", NULL,
	ARRAYSIZE(kcpdclqlc_dpapi), kcpdclqlc_dpapi, NULL, NULL
};

NTSTATUS kcpdclqldpapi_masterkeys(int argc, wchar_t * argv[])
{
	PKULL_M_DPAPI_MASTERKEYS masterkeys;
	PBYTE buffer;
	DWORD szBuffer;

	if(argc && ydeuclqlfile_readData(argv[0], &buffer, &szBuffer))
	{
		if(masterkeys = ydeuclqldpapi_masterkeys_create(buffer))
		{
			ydeuclqldpapi_masterkeys_descr(masterkeys);
			ydeuclqldpapi_masterkeys_delete(masterkeys);
		}
		LocalFree(buffer);
	}
	return STATUS_SUCCESS;
}