/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "../modules/ydeuclqlprocess.h"

typedef struct _REMOTE_LIB_OUTPUT_DATA {
	PVOID		outputVoid;
	DWORD		outputDword;
	NTSTATUS	outputStatus;
	DWORD		outputSize;
	PVOID		outputData;
} REMOTE_LIB_OUTPUT_DATA, *PREMOTE_LIB_OUTPUT_DATA;

typedef struct _REMOTE_LIB_INPUT_DATA {
	PVOID		inputVoid;
	DWORD		inputDword;
	DWORD		inputSize;
	BYTE		inputData[ANYSIZE_ARRAY];
} REMOTE_LIB_INPUT_DATA, *PREMOTE_LIB_INPUT_DATA;

typedef struct _REMOTE_LIB_DATA {
	REMOTE_LIB_OUTPUT_DATA	output;
	REMOTE_LIB_INPUT_DATA	input;
} REMOTE_LIB_DATA, *PREMOTE_LIB_DATA;

typedef struct _REMOTE_EXT {
	PCWCHAR	Module;
	PCHAR	Function;
	PVOID	ToReplace;
	PVOID	Pointer;
} REMOTE_EXT, *PREMOTE_EXT;

typedef struct _MULTIPLE_REMOTE_EXT {
	DWORD count;
	PREMOTE_EXT extensions;
} MULTIPLE_REMOTE_EXT, *PMULTIPLE_REMOTE_EXT;

BOOL CALLBACK ydeuclqlremotelib_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);
PREMOTE_LIB_INPUT_DATA ydeuclqlremotelib_CreateInput(PVOID inputVoid, DWORD inputDword, DWORD inputSize, LPCVOID inputData);
BOOL ydeuclqlremotelib_create(PKULL_M_MEMORY_ADDRESS aRemoteFunc, PREMOTE_LIB_INPUT_DATA input, PREMOTE_LIB_OUTPUT_DATA output);

BOOL CALLBACK ydeuclqlremotelib_exports_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);
BOOL CALLBACK ydeuclqlremotelib_exports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL ydeuclqlremotelib_GetProcAddressMultipleModules(PKULL_M_MEMORY_HANDLE hProcess, PMULTIPLE_REMOTE_EXT extForCb);
BOOL ydeuclqlremotelib_CreateRemoteCodeWitthPatternReplace(PKULL_M_MEMORY_HANDLE hProcess, LPCVOID Buffer, DWORD BufferSize, PMULTIPLE_REMOTE_EXT RemoteExt, PKULL_M_MEMORY_ADDRESS DestAddress);