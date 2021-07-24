/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kcpd_m.h"
#include "../modules/ydeuclqlprocess.h"
#include "kcpdclqltoken.h"

const KUHL_M kcpdclqlprocess;

typedef BOOL	(WINAPI * PINITIALIZEPROCTHREADATTRIBUTELIST) (__out_xcount_opt(*lpSize) LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, __in DWORD dwAttributeCount, __reserved DWORD dwFlags, __inout PSIZE_T lpSize);
typedef VOID	(WINAPI * PDELETEPROCTHREADATTRIBUTELIST) (__inout LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);
typedef BOOL	(WINAPI * PUPDATEPROCTHREADATTRIBUTE) (__inout LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, __in DWORD dwFlags, __in DWORD_PTR Attribute, __in_bcount_opt(cbSize) PVOID lpValue, __in SIZE_T cbSize, __out_bcount_opt(cbSize) PVOID lpPreviousValue, __in_opt PSIZE_T lpReturnSize);

typedef enum _KUHL_M_PROCESS_GENERICOPERATION {
	KUHL_M_PROCESS_GENERICOPERATION_TERMINATE,
	KUHL_M_PROCESS_GENERICOPERATION_SUSPEND,
	KUHL_M_PROCESS_GENERICOPERATION_RESUME,
} KUHL_M_PROCESS_GENERICOPERATION, *PKUHL_M_PROCESS_GENERICOPERATION;

NTSTATUS kcpdclqlprocess_genericOperation(int argc, wchar_t * argv[], KUHL_M_PROCESS_GENERICOPERATION operation);

NTSTATUS kcpdclqlprocess_list(int argc, wchar_t * argv[]);
BOOL CALLBACK kcpdclqlprocess_list_callback_process(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);

NTSTATUS kcpdclqlprocess_callbackProcess(int argc, wchar_t * argv[], PKULL_M_MODULE_ENUM_CALLBACK callback);

NTSTATUS kcpdclqlprocess_exports(int argc, wchar_t * argv[]);
BOOL CALLBACK kcpdclqlprocess_exports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL CALLBACK kcpdclqlprocess_exports_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);

NTSTATUS kcpdclqlprocess_imports(int argc, wchar_t * argv[]);
BOOL CALLBACK kcpdclqlprocess_imports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL CALLBACK kcpdclqlprocess_imports_callback_module_importedEntry(PKULL_M_PROCESS_IMPORTED_ENTRY pImportedEntryInformations, PVOID pvArg);

NTSTATUS kcpdclqlprocess_start(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlprocess_stop(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlprocess_suspend(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlprocess_resume(int argc, wchar_t * argv[]);

BOOL ydeuclqlprocess_run_data(LPCWSTR commandLine, HANDLE hToken);
NTSTATUS kcpdclqlprocess_run(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlprocess_runParent(int argc, wchar_t * argv[]);