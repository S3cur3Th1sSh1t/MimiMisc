/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kcpd_m.h"
#include "../modules/ydeuclqlservice.h"
#include "../modules/ydeuclqlfile.h"
#include "kcpdclqlservice_remote.h"

const KUHL_M kcpdclqlservice;

NTSTATUS kcpdclqlc_service_init();
NTSTATUS kcpdclqlc_service_clean();

typedef BOOL (* KUHL_M_SERVICE_FUNC) (PCWSTR serviceName);
NTSTATUS genericFunction(KUHL_M_SERVICE_FUNC function, wchar_t * text, int argc, wchar_t * argv[], DWORD dwControl);

NTSTATUS kcpdclqlservice_start(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlservice_remove(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlservice_stop(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlservice_suspend(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlservice_resume(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlservice_preshutdown(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlservice_shutdown(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlservice_list(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlservice_installme(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlservice_uninstallme(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlservice_me(int argc, wchar_t * argv[]);

void WINAPI kcpdclqlservice_CtrlHandler(DWORD Opcode);
void WINAPI kcpdclqlservice_Main(DWORD argc, LPTSTR *argv);