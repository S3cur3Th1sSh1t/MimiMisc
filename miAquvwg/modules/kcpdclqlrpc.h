/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kcpd_m.h"
#include "../miAquvwg.h"
#include "../../modules/rpc/ydeuclqlrpc_mimicom.h"

const KUHL_M kcpdclqlrpc;

NTSTATUS kcpdclqlc_rpc_init();
NTSTATUS kcpdclqlc_rpc_clean();

NTSTATUS kcpdclqlrpc_server(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlrpc_connect(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlrpc_enum(int argc, wchar_t * argv[]);

NTSTATUS kcpdclqlrpc_close(int argc, wchar_t * argv[]);

NTSTATUS kcpdclqlrpc_do(wchar_t * input);

typedef struct _KUHL_M_RPC_SERVER_INF {
	PWSTR szProtSeq;
	PWSTR szEndpoint;
	PWSTR szService;
	BOOL publishMe;
	RPC_IF_HANDLE srvif;
	DWORD AuthnSvc;
	DWORD flags;
	RPC_IF_CALLBACK_FN *sec;
} KUHL_M_RPC_SERVER_INF, *PKUHL_M_RPC_SERVER_INF;


//DWORD WINAPI kcpdclqlrpc_server_start(LPVOID lpThreadParameter);