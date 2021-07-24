/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "ydeuclqlrpc.h"

LPCWSTR KULL_M_RPC_AUTHNLEV[7] = {L"DEFAULT", L"NONCE", L"CONNECT", L"CALL", L"PKT", L"PKT_INTEGRITY", L"PKT_PRIVACY",};
LPCWSTR KULL_M_RPC_AUTHNSVC(DWORD AuthnSvc)
{
	LPCWSTR szAuthnSvc;
	switch(AuthnSvc)
	{
	case RPC_C_AUTHN_NONE:
		szAuthnSvc = L"NONE";
		break;
	case RPC_C_AUTHN_GSS_NEGOTIATE:
		szAuthnSvc = L"GSS_NEGOTIATE";
		break;
	case RPC_C_AUTHN_WINNT:
		szAuthnSvc = L"WINNT";
		break;
	case RPC_C_AUTHN_GSS_KERBEROS:
		szAuthnSvc = L"GSS_KERBEROS";
		break;
	case RPC_C_AUTHN_DEFAULT:
		szAuthnSvc = L"DEFAULT";
		break;
	default:
		szAuthnSvc = L"?";
	}
	return szAuthnSvc;
}
const SEC_WINNT_AUTH_IDENTITY KULL_M_RPC_NULLSESSION = {(unsigned short __RPC_FAR *) L"", 0, (unsigned short __RPC_FAR *) L"", 0, (unsigned short __RPC_FAR *) L"", 0, SEC_WINNT_AUTH_IDENTITY_UNICODE};

BOOL ydeuclqlrpc_createBinding(LPCWSTR uuid, LPCWSTR ProtSeq, LPCWSTR NetworkAddr, LPCWSTR Endpoint, LPCWSTR Service, BOOL addServiceToNetworkAddr, DWORD AuthnSvc, RPC_AUTH_IDENTITY_HANDLE hAuth, DWORD ImpersonationType, RPC_BINDING_HANDLE *hBinding, void (RPC_ENTRY * RpcSecurityCallback)(void *))
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	RPC_WSTR StringBinding = NULL;
	RPC_SECURITY_QOS SecurityQOS = {RPC_C_SECURITY_QOS_VERSION, RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH | (ImpersonationType == RPC_C_IMP_LEVEL_DELEGATE) ? RPC_C_QOS_CAPABILITIES_IGNORE_DELEGATE_FAILURE : 0, RPC_C_QOS_IDENTITY_STATIC, ImpersonationType};
	LPWSTR fullServer = NULL;

	*hBinding = NULL;
	rpcStatus = RpcStringBindingCompose((RPC_WSTR) uuid, (RPC_WSTR) ProtSeq, (RPC_WSTR) NetworkAddr, (RPC_WSTR) Endpoint, NULL, &StringBinding);
	if(rpcStatus == RPC_S_OK)
	{
		rpcStatus = RpcBindingFromStringBinding(StringBinding, hBinding);
		if(rpcStatus == RPC_S_OK)
		{
			if(*hBinding)
			{
				if(AuthnSvc != RPC_C_AUTHN_NONE)
				{
					if(addServiceToNetworkAddr)
					{
						if(Service && NetworkAddr)
						{
							ydeuclqlstring_sprintf(&fullServer, L"%s/%s", Service, NetworkAddr);
						}
						else PRINT_ERROR(L"Cannot add Service to NetworkAddr if NULL\n");
					}

					if(!addServiceToNetworkAddr || fullServer)
					{
						rpcStatus = RpcBindingSetAuthInfoEx(*hBinding, (RPC_WSTR) (fullServer ? fullServer : (Service ? Service : AHFIEEIO)), RPC_C_AUTHN_LEVEL_PKT_PRIVACY, AuthnSvc, hAuth, RPC_C_AUTHZ_NONE, &SecurityQOS);
						if(rpcStatus == RPC_S_OK)
						{
							if(RpcSecurityCallback)
							{
								rpcStatus = RpcBindingSetOption(*hBinding, RPC_C_OPT_SECURITY_CALLBACK, (ULONG_PTR) RpcSecurityCallback);
								status = (rpcStatus == RPC_S_OK);
								if(!status)
									PRINT_ERROR(L"RpcBindingSetOption: 0x%08x (%u)\n", rpcStatus, rpcStatus);
							}
							else status = TRUE;
						}
						else PRINT_ERROR(L"RpcBindingSetAuthInfoEx: 0x%08x (%u)\n", rpcStatus, rpcStatus);
					}
				}
				else status = TRUE;

				if(!status)
				{
					rpcStatus = RpcBindingFree(hBinding);
					if(rpcStatus == RPC_S_OK)
						*hBinding = NULL;
					else PRINT_ERROR(L"RpcBindingFree: 0x%08x (%u)\n", rpcStatus, rpcStatus);
				}
			}
			else PRINT_ERROR(L"No Binding!\n");
		}
		else PRINT_ERROR(L"RpcBindingFromStringBinding: 0x%08x (%u)\n", rpcStatus, rpcStatus);
		RpcStringFree(&StringBinding);
	}
	else PRINT_ERROR(L"RpcStringBindingCompose: 0x%08x (%u)\n", rpcStatus, rpcStatus);

	if(fullServer)
	{
		LocalFree(fullServer);
	}

	return status;
}

BOOL ydeuclqlrpc_deleteBinding(RPC_BINDING_HANDLE *hBinding)
{
	BOOL status = FALSE;
	if(status = (RpcBindingFree(hBinding) == RPC_S_OK))
		*hBinding = NULL;
	return status;
}

RPC_STATUS CALLBACK ydeuclqlrpc_nice_SecurityCallback(RPC_IF_HANDLE hInterface, void *pBindingHandle)
{
    return RPC_S_OK;
}

RPC_STATUS CALLBACK ydeuclqlrpc_nice_verb_SecurityCallback(RPC_IF_HANDLE hInterface, void *pBindingHandle)
{
	RPC_STATUS status;
	RPC_AUTHZ_HANDLE hAuthz;
	RPC_WSTR ServerPrincName;
	DWORD AuthnLevel, AuthnSvc, AuthzSvc;
	LPCWSTR szAuthnLevel, szAuthnSvc;

	kprintf(L"** Security Callback! **\n");
	status = RpcBindingInqAuthClient(pBindingHandle, &hAuthz, &ServerPrincName, &AuthnLevel, &AuthnSvc, &AuthzSvc);
	if(status == RPC_S_OK)
	{
		szAuthnLevel = (AuthnLevel < ARRAYSIZE(KULL_M_RPC_AUTHNLEV)) ? KULL_M_RPC_AUTHNLEV[AuthnLevel] : L"?";
		szAuthnSvc = KULL_M_RPC_AUTHNSVC(AuthnSvc);
		kprintf(L" > ServerPrincName: %s\n"
				L" > AuthnLevel     : %2u - %s\n"
				L" > AuthnSvc       : %2u - %s\n"
				L" > AuthzSvc       : %2u\n", ServerPrincName, AuthnLevel, szAuthnLevel, AuthnSvc, szAuthnSvc, AuthzSvc);
		RpcStringFree(&ServerPrincName);
		RpcImpersonateClient(pBindingHandle);
		RpcRevertToSelf();
	}
	else if(status == RPC_S_BINDING_HAS_NO_AUTH)
		kprintf(L" > No Authentication\n");
	else PRINT_ERROR(L"RpcBindingInqAuthClient: %08x\n", status);
    return RPC_S_OK;
}

void ydeuclqlrpc_getArgs(int argc, wchar_t * argv[], LPCWSTR *szRemote, LPCWSTR *szProtSeq, LPCWSTR *szEndpoint, LPCWSTR *szService, LPCWSTR szDefaultService, DWORD *AuthnSvc, DWORD defAuthnSvc, BOOL *isNullSession, SEC_WINNT_AUTH_IDENTITY *pAuthIdentity, GUID *altGuid, BOOL printIt)
{
	PCWSTR data;
	UNICODE_STRING us;

	if(szRemote)
	{
		if(!ydeuclqlstring_args_byName(argc, argv, L"remote", szRemote, NULL))
			if(!ydeuclqlstring_args_byName(argc, argv, L"server", szRemote, NULL))
				ydeuclqlstring_args_byName(argc, argv, L"target", szRemote, NULL);
		if(printIt)
			kprintf(L"[rpc] Remote   : %s\n", *szRemote);
	}

	if(szProtSeq)
	{
		ydeuclqlstring_args_byName(argc, argv, L"protseq", szProtSeq, L"ncacn_ip_tcp");
		if(printIt)
			kprintf(L"[rpc] ProtSeq  : %s\n", *szProtSeq);
	}
	
	if(szEndpoint)
	{
		ydeuclqlstring_args_byName(argc, argv, L"endpoint", szEndpoint, NULL);
		if(printIt)
			kprintf(L"[rpc] Endpoint : %s\n", *szEndpoint);
	}
	
	if(szService)
	{
		if(!ydeuclqlstring_args_byName(argc, argv, L"service", szService, NULL))
			ydeuclqlstring_args_byName(argc, argv, L"altservice", szService, szDefaultService);
		if(printIt)
			kprintf(L"[rpc] Service  : %s\n", *szService);
	}
	
	if(AuthnSvc)
	{
		if(ydeuclqlstring_args_byName(argc, argv, L"noauth", NULL, NULL))
			*AuthnSvc = RPC_C_AUTHN_NONE;
		else if(ydeuclqlstring_args_byName(argc, argv, L"ntlm", NULL, NULL))
			*AuthnSvc = RPC_C_AUTHN_WINNT;
		else if(ydeuclqlstring_args_byName(argc, argv, L"kerberos", NULL, NULL))
			*AuthnSvc = RPC_C_AUTHN_GSS_KERBEROS;
		else if(ydeuclqlstring_args_byName(argc, argv, L"negotiate", NULL, NULL))
			*AuthnSvc = RPC_C_AUTHN_GSS_NEGOTIATE;
		else *AuthnSvc = defAuthnSvc;
		if(printIt)
			kprintf(L"[rpc] AuthnSvc : %s (%u)\n", KULL_M_RPC_AUTHNSVC(*AuthnSvc), *AuthnSvc);
	}

	if(isNullSession)
	{
		*isNullSession = ydeuclqlstring_args_byName(argc, argv, L"null", NULL, NULL);
		if(printIt)
			kprintf(L"[rpc] NULL Sess: %s\n", (*isNullSession) ? L"yes" : L"no");
	}

	if(pAuthIdentity && (!isNullSession || !*isNullSession))
	{
		pAuthIdentity->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

		ydeuclqlstring_args_byName(argc, argv, L"authuser", (const wchar_t **) &pAuthIdentity->User, L"");
		pAuthIdentity->UserLength = lstrlen((LPCWSTR) pAuthIdentity->User);
		ydeuclqlstring_args_byName(argc, argv, L"authdomain", (const wchar_t **) &pAuthIdentity->Domain, L"");
		pAuthIdentity->DomainLength = lstrlen((LPCWSTR) pAuthIdentity->Domain);
		ydeuclqlstring_args_byName(argc, argv, L"authpassword", (const wchar_t **) &pAuthIdentity->Password, L"");
		pAuthIdentity->PasswordLength = lstrlen((LPCWSTR) pAuthIdentity->Password);

		if(pAuthIdentity->UserLength)
		{
			kprintf(L"[rpc] Username : %s\n[rpc] Domain   : %s\n[rpc] Password : %s\n", pAuthIdentity->User, pAuthIdentity->Domain, pAuthIdentity->Password);
		}
	}

	if(altGuid)
	{
		if(ydeuclqlstring_args_byName(argc, argv, L"guid", &data, NULL))
		{
			RtlInitUnicodeString(&us, data);
			if(NT_SUCCESS(RtlGUIDFromString(&us, altGuid)) && printIt)
			{
				kprintf(L"[rpc] Alt GUID : ");
				ydeuclqlstring_displayGUID(altGuid);
				kprintf(L"\n");
			}
		}
	}
}

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t cBytes)
{
	return LocalAlloc(LPTR, cBytes);
}

void __RPC_USER midl_user_free(void __RPC_FAR * p)
{
	if(p)
		LocalFree(p);
}

void __RPC_USER ReadFcn(void *State, char **pBuffer, unsigned int *pSize)
{
	*pBuffer = (char *) ((PKULL_M_RPC_FCNSTRUCT) State)->addr;
	((PKULL_M_RPC_FCNSTRUCT) State)->addr = *pBuffer + *pSize;
	((PKULL_M_RPC_FCNSTRUCT) State)->size -= *pSize;
}

void __RPC_USER WriteFcn(void *State, char *Buffer, unsigned int Size)
{
}

void __RPC_USER AllocFcn (void *State, char **pBuffer, unsigned int *pSize)
{
}

BOOL ydeuclqlrpc_Generic_Decode(PVOID data, DWORD size, PVOID pObject, PGENERIC_RPC_DECODE fDecode)
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	PVOID buffer;
	KULL_M_RPC_FCNSTRUCT UserState ;
	handle_t pHandle;

	if(buffer = UserState.addr = LocalAlloc(LPTR, size))
	{
		UserState.size = size;
		RtlCopyMemory(UserState.addr, data, size); // avoid data alteration
		rpcStatus = MesDecodeIncrementalHandleCreate(&UserState, ReadFcn, &pHandle);
		if(NT_SUCCESS(rpcStatus))
		{
			rpcStatus = MesIncrementalHandleReset(pHandle, NULL, NULL, NULL, NULL, MES_DECODE);
			if(NT_SUCCESS(rpcStatus))
			{
				RpcTryExcept
				{
					fDecode(pHandle, pObject);
					status = TRUE;
				}
				RpcExcept(EXCEPTION_EXECUTE_HANDLER)
					PRINT_ERROR(L"RPC Exception: 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
				RpcEndExcept
			}
			else PRINT_ERROR(L"MesIncrementalHandleReset: %08x\n", rpcStatus);
			MesHandleFree(pHandle);
		}
		else PRINT_ERROR(L"MesDecodeIncrementalHandleCreate: %08x\n", rpcStatus);
		LocalFree(buffer);
	}
	return status;
}

void ydeuclqlrpc_Generic_Free(PVOID pObject, PGENERIC_RPC_FREE fFree)
{
	RPC_STATUS rpcStatus;
	KULL_M_RPC_FCNSTRUCT UserState = {NULL, 0};
	handle_t pHandle;

	rpcStatus = MesDecodeIncrementalHandleCreate(&UserState, ReadFcn, &pHandle); // for legacy
	if(NT_SUCCESS(rpcStatus))
	{
		RpcTryExcept
			fFree(pHandle, pObject);
		RpcExcept(EXCEPTION_EXECUTE_HANDLER)
			PRINT_ERROR(L"RPC Exception: 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
		RpcEndExcept
		MesHandleFree(pHandle);
	}
	else PRINT_ERROR(L"MesDecodeIncrementalHandleCreate: %08x\n", rpcStatus);
}

BOOL ydeuclqlrpc_Generic_Encode(PVOID pObject, PVOID *data, DWORD *size, PGENERIC_RPC_ENCODE fEncode, PGENERIC_RPC_ALIGNSIZE fAlignSize)
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	KULL_M_RPC_FCNSTRUCT UserState;
	handle_t pHandle;

	rpcStatus = MesEncodeIncrementalHandleCreate(&UserState, ReadFcn, WriteFcn, &pHandle);
	if(NT_SUCCESS(rpcStatus))
	{
		*size = (DWORD) fAlignSize(pHandle, pObject);
		if(*data = LocalAlloc(LPTR, *size))
		{
			rpcStatus = MesIncrementalHandleReset(pHandle, NULL, NULL, NULL, NULL, MES_ENCODE);
			if(NT_SUCCESS(rpcStatus))
			{
				UserState.addr = *data;
				UserState.size = *size;
				RpcTryExcept
				{
					fEncode(pHandle, pObject);
					status = TRUE;
				}
				RpcExcept(EXCEPTION_EXECUTE_HANDLER)
					PRINT_ERROR(L"RPC Exception: 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
				RpcEndExcept
			}
			else PRINT_ERROR(L"MesIncrementalHandleReset: %08x\n", rpcStatus);

			if(!status)
			{
				*data = LocalFree(*data);
				*size = 0;
			}
		}
		MesHandleFree(pHandle);
	}
	else PRINT_ERROR(L"MesEncodeIncrementalHandleCreate: %08x\n", rpcStatus);
	return status;
}

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
const BYTE KULL_M_RPC_FIND_STUB_PATTERN[] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};//, 0x00, 0x00, 0x02};
#elif defined(_M_IX86)
const BYTE KULL_M_RPC_FIND_STUB_PATTERN[] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#endif 
PMIDL_STUB_DESC ydeuclqlrpc_find_stub(LPCWSTR szModuleName, const RPC_SYNTAX_IDENTIFIER *pInterfaceId)
{
	PMIDL_STUB_DESC pReturnStub = NULL, pCandidateStub;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION information;
	KULL_M_MEMORY_ADDRESS aToSearch = {(LPVOID) KULL_M_RPC_FIND_STUB_PATTERN, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory;

	if(ydeuclqlprocess_getVeryBasicModuleInformationsForName(&KULL_M_MEMORY_GLOBAL_OWN_HANDLE, szModuleName, &information))
	{
		sMemory.ydeuclqlmemoryRange.ydeuclqlmemoryAdress = information.DllBase;
		sMemory.ydeuclqlmemoryRange.size = information.SizeOfImage;
		while(ydeuclqlmemory_search(&aToSearch, sizeof(KULL_M_RPC_FIND_STUB_PATTERN), &sMemory, FALSE))
		{
			pCandidateStub = (PMIDL_STUB_DESC) ((PBYTE) sMemory.result - (FIELD_OFFSET(MIDL_STUB_DESC, MIDLVersion) + 3));
			if(pCandidateStub->RpcInterfaceInformation && ((PBYTE) pCandidateStub->RpcInterfaceInformation >= (PBYTE) information.DllBase.address) && ((PBYTE) pCandidateStub->RpcInterfaceInformation < ((PBYTE) information.DllBase.address + information.SizeOfImage)))
			{
				if(RtlEqualMemory(pInterfaceId, &((PRPC_CLIENT_INTERFACE) pCandidateStub->RpcInterfaceInformation)->InterfaceId, sizeof(RPC_SYNTAX_IDENTIFIER)))
				{
					pReturnStub = pCandidateStub;
					break;
				}
			}
			sMemory.ydeuclqlmemoryRange.size -= ((PBYTE) sMemory.result + sizeof(KULL_M_RPC_FIND_STUB_PATTERN)) - (PBYTE) sMemory.ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address;
			sMemory.ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address = (PBYTE) sMemory.result + sizeof(KULL_M_RPC_FIND_STUB_PATTERN);
		}
	}
	else PRINT_ERROR(L"ydeuclqlprocess_getVeryBasicModuleInformationsForName for %s\n", szModuleName);

	return pReturnStub;
}

BOOL ydeuclqlrpc_replace_first_routine_pair_direct(const GENERIC_BINDING_ROUTINE_PAIR *pOriginalBindingPair, const GENERIC_BINDING_ROUTINE_PAIR *pNewBindingPair)
{
	BOOL status = FALSE;
	DWORD dwOldProtect;

	if(VirtualProtect((LPVOID) pOriginalBindingPair, sizeof(GENERIC_BINDING_ROUTINE_PAIR), PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		((PGENERIC_BINDING_ROUTINE_PAIR) pOriginalBindingPair)[0] = *pNewBindingPair;
		status = TRUE;
		if(!VirtualProtect((LPVOID) pOriginalBindingPair, sizeof(GENERIC_BINDING_ROUTINE_PAIR), dwOldProtect, &dwOldProtect))
		{
			PRINT_ERROR_AUTO(L"VirtualProtect(post)");
		}
	}
	else PRINT_ERROR_AUTO(L"VirtualProtect(pre)");

	return status;
}

BOOL ydeuclqlrpc_replace_first_routine_pair(LPCWSTR szModuleName, const RPC_SYNTAX_IDENTIFIER *pInterfaceId, const GENERIC_BINDING_ROUTINE_PAIR *pNewBindingPair, PGENERIC_BINDING_ROUTINE_PAIR pOriginalBindingPair, const GENERIC_BINDING_ROUTINE_PAIR **ppOriginalBindingPair)
{
	BOOL status = FALSE;
	PMIDL_STUB_DESC pStub;

	pStub = ydeuclqlrpc_find_stub(szModuleName, pInterfaceId);
	if(pStub)
	{
		if(pStub->aGenericBindingRoutinePairs)
		{
			if(ppOriginalBindingPair)
			{
				*ppOriginalBindingPair = pStub->aGenericBindingRoutinePairs;
			}
			if(pOriginalBindingPair)
			{
				*pOriginalBindingPair = pStub->aGenericBindingRoutinePairs[0];
			}
			status = ydeuclqlrpc_replace_first_routine_pair_direct(pStub->aGenericBindingRoutinePairs, pNewBindingPair);
		}
		else PRINT_ERROR(L"No GenericBindingRoutinePairs\n");
	}
	else PRINT_ERROR(L"Stub not found\n");

	return status;
}