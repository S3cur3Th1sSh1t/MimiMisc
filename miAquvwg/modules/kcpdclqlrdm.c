/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "kcpdclqlrdm.h"

const KUHL_M_C kcpdclqlc_rdm[] = {
	{kcpdclqlrdm_version,	L"version",	NULL},
	{kcpdclqlrdm_list,		L"list", NULL},
};
const KUHL_M kcpdclqlrdm = {
	L"rdm", L"RF module for RDM(830 AL) device", NULL,
	ARRAYSIZE(kcpdclqlc_rdm), kcpdclqlc_rdm, NULL, NULL
};

NTSTATUS kcpdclqlrdm_version(int argc, wchar_t * argv[])
{
	PRDM_DEVICE devices, cur;
	ULONG count;
	PSTR version;

	if(rdm_devices_get(&devices, &count))
	{
		for(cur = devices; cur; cur = cur->next)
		{
			kprintf(L"[%3u] ", cur->id);
			if(rdm_get_version(cur->hDevice, &version))
			{
				kprintf(L"%S\n", version);
				LocalFree(version);
			}
		}
		rdm_devices_free(devices);
	}
	else PRINT_ERROR(L"No device found\n");
	return STATUS_SUCCESS;
}


NTSTATUS kcpdclqlrdm_list(int argc, wchar_t * argv[])
{
	PRDM_DEVICE devices, cur;
	ULONG count;
	if(rdm_devices_get(&devices, &count))
	{
		for(cur = devices; cur; cur = cur->next)
			kprintf(L"\n[%3u] %s\n  Vendor: 0x%04x, Product: 0x%04x, Version: 0x%04x\n", cur->id, cur->DevicePath, cur->hidAttributes.VendorID, cur->hidAttributes.ProductID, cur->hidAttributes.VersionNumber);
		rdm_devices_free(devices);
	}
	else PRINT_ERROR(L"No device found\n");
	return STATUS_SUCCESS;
}