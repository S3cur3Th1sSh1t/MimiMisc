/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "kcpdclqlservice.h"

const KUHL_M_C kcpdclqlc_service[] = {
	{kcpdclqlservice_start,		L"start",		L"Start service"},
	{kcpdclqlservice_remove,		L"remove",		L"Remove service"},
	{kcpdclqlservice_stop,		L"stop",		L"Stop service"},
	{kcpdclqlservice_suspend,	L"suspend",		L"Suspend service"},
	{kcpdclqlservice_resume,		L"resume",		L"Resume service"},
	{kcpdclqlservice_preshutdown,L"preshutdown",	L"Preshutdown service"},
	{kcpdclqlservice_shutdown,	L"shutdown",	L"Shutdown service"},
	{kcpdclqlservice_list,		L"list",		L"List services"},
	{kcpdclqlservice_installme,	L"+",			L"Install Me!"},
	{kcpdclqlservice_uninstallme,L"-",			L"Install Me!"},
	{kcpdclqlservice_me,			L"me",			L"Me!"},
};

const KUHL_M kcpdclqlservice = {
	L"service", L"Service module", NULL,
	ARRAYSIZE(kcpdclqlc_service), kcpdclqlc_service, kcpdclqlc_service_init, kcpdclqlc_service_clean
};

SERVICE_STATUS m_ServiceStatus = {SERVICE_WIN32_OWN_PROCESS, SERVICE_STOPPED, 0, NO_ERROR, 0, 0, 0};
SERVICE_STATUS_HANDLE m_ServiceStatusHandle;
HANDLE hceFdEventRunning;

NTSTATUS kcpdclqlc_service_init()
{
	m_ServiceStatusHandle = NULL;
	hceFdEventRunning = NULL;
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlc_service_clean()
{
	if(m_ServiceStatusHandle)
		kcpdclqlservice_CtrlHandler(SERVICE_STOP);
	return STATUS_SUCCESS;
}

NTSTATUS genericFunction(KUHL_M_SERVICE_FUNC function, wchar_t * text, int argc, wchar_t * argv[], DWORD dwControl)
{
	if(argc)
	{
		kprintf(L"%s \'%s\' service : ", text, argv[0]);
		if(argc == 1)
		{
			if(function(argv[0]))
				kprintf(L"OK\n");
			else PRINT_ERROR_AUTO(L"Service operation");
		}
#if defined(SERVICE_INCONTROL)
		else if(dwControl && (AHFIEEIO_NT_BUILD_NUMBER >= KULL_M_WIN_BUILD_7))
		{
			kcpd_service_sendcontrol_inprocess(argv[0], dwControl);
		}
		else PRINT_ERROR(L"Inject not available\n");
#endif
	}
	else PRINT_ERROR(L"Missing service name argument\n");

	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlservice_start(int argc, wchar_t * argv[])
{
	return genericFunction(ydeuclqlservice_start, L"Starting", argc, argv, 0);
}

NTSTATUS kcpdclqlservice_remove(int argc, wchar_t * argv[])
{
	return genericFunction(ydeuclqlservice_remove, L"Removing", argc, argv, 0);
}

NTSTATUS kcpdclqlservice_stop(int argc, wchar_t * argv[])
{
	return genericFunction(ydeuclqlservice_stop, L"Stopping", argc, argv, SERVICE_CONTROL_STOP);
}

NTSTATUS kcpdclqlservice_suspend(int argc, wchar_t * argv[])
{
	return genericFunction(ydeuclqlservice_suspend, L"Suspending", argc, argv, SERVICE_CONTROL_PAUSE);
}

NTSTATUS kcpdclqlservice_resume(int argc, wchar_t * argv[])
{
	return genericFunction(ydeuclqlservice_resume, L"Resuming", argc, argv, SERVICE_CONTROL_CONTINUE);
}

NTSTATUS kcpdclqlservice_preshutdown(int argc, wchar_t * argv[])
{
	return genericFunction(ydeuclqlservice_preshutdown, L"Preshutdown", argc, argv, SERVICE_CONTROL_PRESHUTDOWN);
}

NTSTATUS kcpdclqlservice_shutdown(int argc, wchar_t * argv[])
{
	return genericFunction(ydeuclqlservice_shutdown, L"Shutdown", argc, argv, SERVICE_CONTROL_SHUTDOWN);
}

NTSTATUS kcpdclqlservice_list(int argc, wchar_t * argv[])
{
	return STATUS_SUCCESS;
}

const wchar_t kcpdclqlservice_installme_args[] = L"rpc::server service::me exit";
NTSTATUS kcpdclqlservice_installme(int argc, wchar_t * argv[])
{
#pragma warning(push)
#pragma warning(disable:4996)	
	wchar_t *fileName = _wpgmptr;
#pragma warning(pop)
	wchar_t *absFile, *buff;
	DWORD size;

	if(ydeuclqlfile_getAbsolutePathOf(fileName, &absFile))
	{
		if(ydeuclqlfile_isFileExist(absFile))
		{
			size = 1 + lstrlen(absFile) + 1 + 1 + lstrlen(kcpdclqlservice_installme_args) + 1;
			if(buff = (wchar_t *) LocalAlloc(LPTR, size * sizeof(wchar_t)))
			{
				wcscat_s(buff, size, L"\"");
				wcscat_s(buff, size, absFile);
				wcscat_s(buff, size, L"\" ");
				wcscat_s(buff, size, kcpdclqlservice_installme_args);
				ydeuclqlservice_install(AHFIEEIO_SERVICE, AHFIEEIO L" service (" AHFIEEIO_SERVICE L")", buff, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, TRUE);
				LocalFree(buff);
			}
		}
		else PRINT_ERROR_AUTO(L"ydeuclqlfile_isFileExist");
		LocalFree(absFile);
	}
	else PRINT_ERROR_AUTO(L"ydeuclqlfile_getAbsolutePathOf");
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlservice_uninstallme(int argc, wchar_t * argv[])
{
	ydeuclqlservice_uninstall(AHFIEEIO_SERVICE);
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlservice_me(int argc, wchar_t * argv[])
{
	const SERVICE_TABLE_ENTRY DispatchTable[]= {{AHFIEEIO_SERVICE, kcpdclqlservice_Main}, {NULL, NULL}};
	if(hceFdEventRunning = CreateEvent(NULL, TRUE, FALSE, NULL))
	{
		StartServiceCtrlDispatcher(DispatchTable);
		CloseHandle(hceFdEventRunning);
	}
	return STATUS_SUCCESS;
}

void WINAPI kcpdclqlservice_CtrlHandler(DWORD Opcode)
{
	BOOL notCoded = FALSE;
	switch(Opcode)
	{
		case SERVICE_CONTROL_PAUSE: 
			m_ServiceStatus.dwCurrentState = SERVICE_PAUSED;
			break;
		case SERVICE_CONTROL_CONTINUE:
			m_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
			break;
		case SERVICE_CONTROL_STOP:
		case SERVICE_CONTROL_SHUTDOWN: 
			m_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
			break;
		default:
			notCoded = TRUE;
	}
	if(!notCoded)
	{
		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
		if(m_ServiceStatus.dwCurrentState == SERVICE_STOP_PENDING)
			SetEvent(hceFdEventRunning);
	}
	return;
}

void WINAPI kcpdclqlservice_Main(DWORD argc, LPTSTR *argv)
{
	if(m_ServiceStatusHandle = RegisterServiceCtrlHandler(AHFIEEIO_SERVICE, kcpdclqlservice_CtrlHandler))
	{
		m_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
		m_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
		m_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
		WaitForSingleObject(hceFdEventRunning, INFINITE);
		m_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
		m_ServiceStatusHandle = NULL;
	}
}