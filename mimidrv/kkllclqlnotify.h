/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kkllclqlmemory.h"
#include "kkllclqlmodules.h"

#define OBJECT_HASH_TABLE_SIZE	37
#define CM_REG_MAX_CALLBACKS	100

typedef struct _KKLL_M_NOTIFY_CALLBACK {
#if defined(_M_IX86)
	ULONG unk0;
#endif
	PVOID * callback;
} KKLL_M_NOTIFY_CALLBACK, *PKKLL_M_NOTIFY_CALLBACK;

typedef struct _OBJECT_DIRECTORY_ENTRY {
	struct	_OBJECT_DIRECTORY_ENTRY *	ChainLink;
	PVOID								Object;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY {
	POBJECT_DIRECTORY_ENTRY		HashBuckets[OBJECT_HASH_TABLE_SIZE];
	/* ... */
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

typedef struct _OBJECT_CALLBACK_ENTRY {
	LIST_ENTRY					CallbackList;
	OB_OPERATION				Operations;
	ULONG Active;
	/*OB_HANDLE*/ PVOID Handle;
	POBJECT_TYPE				ObjectType;
	POB_PRE_OPERATION_CALLBACK	PreOperation;
	POB_POST_OPERATION_CALLBACK	PostOperation;
	/* ... */
} OBJECT_CALLBACK_ENTRY, *POBJECT_CALLBACK_ENTRY;

typedef NTSTATUS	(* PPSSETCREATEPROCESSNOTIFYROUTINEEX)	( __in PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine, __in BOOLEAN Remove);
//typedef VOID (* POBUNREGISTERCALLBACKS) (__in PVOID RegistrationHandle);

NTSTATUS kkllclqlnotify_list_thread(PJoAA_BUFFER outBuffer);
NTSTATUS kkllclqlnotify_list_process(PJoAA_BUFFER outBuffer);
NTSTATUS kkllclqlnotify_list_image(PJoAA_BUFFER outBuffer);
NTSTATUS kkllclqlnotify_list_reg(PJoAA_BUFFER outBuffer);
NTSTATUS kkllclqlnotify_list_object(PJoAA_BUFFER outBuffer);
NTSTATUS kkllclqlnotify_desc_object_callback(POBJECT_CALLBACK_ENTRY pCallbackEntry, PJoAA_BUFFER outBuffer);

NTSTATUS kkllclqlnotify_list(PJoAA_BUFFER outBuffer, PKKLL_M_MEMORY_GENERIC generics, SIZE_T cbGenerics, PUCHAR * ptr, PULONG pRoutineMax);
NTSTATUS kkllclqlnotify_search(PKKLL_M_MEMORY_GENERIC generics, SIZE_T cbGenerics, PUCHAR * ptr, PULONG pRoutineMax, PKKLL_M_MEMORY_OFFSETS * pOffsets);