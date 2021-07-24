/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kcpd_m.h"
//#include "lsadump/kcpdclqllsadump_dc.h"
#include "../../modules/ydeuclqlldap.h"
#include "../../modules/ydeuclqlnet.h"
#include "../../modules/ydeuclqltoken.h"
#include "../../modules/rpc/ydeuclqlrpc_ms-dcom_IObjectExporter.h"
#include <WinDNS.h>

const KUHL_M kcpdclqlnet;

NTSTATUS kcpdclqlnet_user(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlnet_group(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlnet_alias(int argc, wchar_t * argv[]);

void kcpdclqlnet_simpleLookup(SAMPR_HANDLE hDomainHandle, DWORD rid);

NTSTATUS kcpdclqlnet_autoda(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlnet_session(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlnet_wsession(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlnet_tod(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlnet_stats(int argc, wchar_t * argv[]);

void kcpdclqlnet_share_type(DWORD type);

NTSTATUS kcpdclqlnet_share(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlnet_serverinfo(int argc, wchar_t * argv[]);

NTSTATUS kcpdclqlnet_trust(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlnet_deleg(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlnet_dcom_if(int argc, wchar_t * argv[]);