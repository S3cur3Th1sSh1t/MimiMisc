/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kcpd_m.h"
#include "../modules/ydeuclqlkernel.h"
#include "../modules/ydeuclqlprocess.h"
#include "../modules/ydeuclqlservice.h"
#include "../modules/ydeuclqlfile.h"
#include "../modules/ydeuclqlstring.h"


typedef struct _KUHL_K_C {
	const PKUHL_M_C_FUNC pCommand;
	const DWORD ioctlCode;
	const wchar_t * command;
	const wchar_t * description;
} KUHL_K_C, *PKUHL_K_C;

NTSTATUS kcpdclqlkernel_do(wchar_t * input);

NTSTATUS kcpdclqlkernel_add_mimidrv(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlkernel_remove_mimidrv(int argc, wchar_t * argv[]);

NTSTATUS kcpdclqlkernel_processProtect(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlkernel_processToken(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlkernel_processPrivilege(int argc, wchar_t * argv[]);
