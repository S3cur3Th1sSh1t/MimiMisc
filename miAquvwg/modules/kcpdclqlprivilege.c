/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "kcpdclqlprivilege.h"

const KUHL_M_C kcpdclqlc_privilege[] = {
	{kcpdclqlprivilege_debug,		L"debug",		L"Ask debug privilege"},
	{kcpdclqlprivilege_driver,		L"driver",		L"Ask load driver privilege"},
	{kcpdclqlprivilege_security,		L"security",	L"Ask security privilege"},
	{kcpdclqlprivilege_tcb,			L"tcb",			L"Ask tcb privilege"},
	{kcpdclqlprivilege_backup,		L"backup",		L"Ask backup privilege"},
	{kcpdclqlprivilege_restore,		L"restore",		L"Ask restore privilege"},
	{kcpdclqlprivilege_sysenv,		L"sysenv",		L"Ask system environment privilege"},

	{kcpdclqlprivilege_id,			L"id",			L"Ask a privilege by its id"},
	{kcpdclqlprivilege_name,			L"name",		L"Ask a privilege by its name"},
};

const KUHL_M kcpdclqlprivilege = {
	L"privilege", L"Privilege module", NULL,
	ARRAYSIZE(kcpdclqlc_privilege), kcpdclqlc_privilege, NULL, NULL
};

NTSTATUS kcpdclqlprivilege_simple(ULONG privId)
{
	ULONG previousState;
	NTSTATUS status = RtlAdjustPrivilege(privId, TRUE, FALSE, &previousState);
	if(NT_SUCCESS(status))
		kprintf(L"Privilege \'%u\' OK\n", privId);
	else PRINT_ERROR(L"RtlAdjustPrivilege (%u) %08x\n", privId, status);
	return status;
}

NTSTATUS kcpdclqlprivilege_id(int argc, wchar_t * argv[])
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	if(argc)
		status = kcpdclqlprivilege_simple(wcstoul(argv[0], NULL, 0));
	else PRINT_ERROR(L"Missing \'id\'\n");
	return status;
}

NTSTATUS kcpdclqlprivilege_name(int argc, wchar_t * argv[])
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	LUID luid;
	if(argc)
	{
		if(LookupPrivilegeValue(NULL, argv[0], &luid))
		{
			if(!luid.HighPart)
				status = kcpdclqlprivilege_simple(luid.LowPart);
			else PRINT_ERROR(L"LUID high part is %u\n", luid.HighPart);
		}
		else PRINT_ERROR_AUTO(L"LookupPrivilegeValue");
	}
	else PRINT_ERROR(L"Missing \'name\'\n");
	return status;
}

NTSTATUS kcpdclqlprivilege_debug(int argc, wchar_t * argv[])
{
	return kcpdclqlprivilege_simple(SE_DEBUG);
}

NTSTATUS kcpdclqlprivilege_driver(int argc, wchar_t * argv[])
{
	return kcpdclqlprivilege_simple(SE_LOAD_DRIVER);
}

NTSTATUS kcpdclqlprivilege_security(int argc, wchar_t * argv[])
{
	return kcpdclqlprivilege_simple(SE_SECURITY);
}

NTSTATUS kcpdclqlprivilege_tcb(int argc, wchar_t * argv[])
{
	return kcpdclqlprivilege_simple(SE_TCB);
}
NTSTATUS kcpdclqlprivilege_backup(int argc, wchar_t * argv[])
{
	return kcpdclqlprivilege_simple(SE_BACKUP);
}

NTSTATUS kcpdclqlprivilege_restore(int argc, wchar_t * argv[])
{
	return kcpdclqlprivilege_simple(SE_RESTORE);
}

NTSTATUS kcpdclqlprivilege_sysenv(int argc, wchar_t * argv[])
{
	return kcpdclqlprivilege_simple(SE_SYSTEM_ENVIRONMENT);
}