/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kcpd_m.h"
#include "../../modules/ydeuclqlstring.h"
#include "../../modules/ydeuclqlfile.h"
#include "../../modules/ydeuclqlprocess.h"
#include "../../modules/ydeuclqlnet.h"
#include "../../modules/ydeuclqlcabinet.h"

const KUHL_M kcpdclqlstandard;

NTSTATUS kcpdclqlstandard_cls(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlstandard_exit(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlstandard_cite(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlstandard_answer(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlstandard_coffee(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlstandard_sleep(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlstandard_log(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlstandard_base64(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlstandard_version(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlstandard_cd(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlstandard_localtime(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlstandard_hostname(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlstandard_test(int argc, wchar_t * argv[]);