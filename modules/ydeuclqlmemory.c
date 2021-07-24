/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "ydeuclqlmemory.h"

KULL_M_MEMORY_HANDLE KULL_M_MEMORY_GLOBAL_OWN_HANDLE = {KULL_M_MEMORY_TYPE_OWN, NULL};

BOOL ydeuclqlmemory_open(IN KULL_M_MEMORY_TYPE Type, IN HANDLE hAny, OUT PKULL_M_MEMORY_HANDLE *hMemory)
{
	BOOL status = FALSE;

	*hMemory = (PKULL_M_MEMORY_HANDLE) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE));
	if(*hMemory)
	{
		(*hMemory)->type = Type;
		switch (Type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			status = TRUE;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			if((*hMemory)->pHandleProcess = (PKULL_M_MEMORY_HANDLE_PROCESS) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE_PROCESS)))
			{
				(*hMemory)->pHandleProcess->hProcess = hAny;
				status = TRUE;
			}
			break;
		case KULL_M_MEMORY_TYPE_FILE:
			if((*hMemory)->pHandleFile = (PKULL_M_MEMORY_HANDLE_FILE) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE_FILE)))
			{
				(*hMemory)->pHandleFile->hFile = hAny;
				status = TRUE;
			}
			break;
		case KULL_M_MEMORY_TYPE_PROCESS_DMP:
			if((*hMemory)->pHandleProcessDmp = (PKULL_M_MEMORY_HANDLE_PROCESS_DMP) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE_PROCESS_DMP)))
				status = ydeuclqlminidump_open(hAny, &(*hMemory)->pHandleProcessDmp->hMinidump);
			break;
		case KULL_M_MEMORY_TYPE_KERNEL:
			if((*hMemory)->pHandleDriver = (PKULL_M_MEMORY_HANDLE_KERNEL) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE_KERNEL)))
			{
				(*hMemory)->pHandleDriver->hDriver = hAny;
				status = TRUE;
			}
			break;
		default:
			break;
		}
		if(!status)
			LocalFree(*hMemory);
	}
	return status;
}

PKULL_M_MEMORY_HANDLE ydeuclqlmemory_close(IN PKULL_M_MEMORY_HANDLE hMemory)
{
	if(hMemory)
	{
		switch (hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_PROCESS:
			LocalFree(hMemory->pHandleProcess);
			break;
		case KULL_M_MEMORY_TYPE_FILE:
			LocalFree(hMemory->pHandleFile);
			break;
		case KULL_M_MEMORY_TYPE_PROCESS_DMP:
			if(hMemory->pHandleProcessDmp)
			{
				ydeuclqlminidump_close(hMemory->pHandleProcessDmp->hMinidump);
				LocalFree(hMemory->pHandleProcessDmp);
			}
			break;
		case KULL_M_MEMORY_TYPE_KERNEL:
			LocalFree(hMemory->pHandleDriver);
			break;
		default:
			break;
		}
		return (PKULL_M_MEMORY_HANDLE) LocalFree(hMemory);
	}
	else return NULL;
}

BOOL ydeuclqlmemory_copy(OUT PKULL_M_MEMORY_ADDRESS Destination, IN PKULL_M_MEMORY_ADDRESS Source, IN SIZE_T Length)
{
	BOOL status = FALSE;
	BOOL bufferMeFirst = FALSE;
	KULL_M_MEMORY_ADDRESS aBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	DWORD nbReadWrite;

	switch(Destination->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		switch(Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			RtlCopyMemory(Destination->address, Source->address, Length);
			status = TRUE;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			status = ReadProcessMemory(Source->hMemory->pHandleProcess->hProcess, Source->address, Destination->address, Length, NULL);
			break;
		case KULL_M_MEMORY_TYPE_PROCESS_DMP:
			status = ydeuclqlminidump_copy(Source->hMemory->pHandleProcessDmp->hMinidump, Destination->address, Source->address, Length);
			break;
		case KULL_M_MEMORY_TYPE_FILE:
			if(SetFilePointer(Source->hMemory->pHandleFile->hFile, PtrToLong(Source->address), NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
				status = ReadFile(Source->hMemory->pHandleFile->hFile, Destination->address, (DWORD) Length, &nbReadWrite, NULL);
			break;
		case KULL_M_MEMORY_TYPE_KERNEL:
			status = ydeuclqlkernel_ioctl_handle(Source->hMemory->pHandleDriver->hDriver, IOCTL_MIMIDRV_VM_READ, Source->address, 0, &Destination->address, (PDWORD) &Length, FALSE);
			break;
		default:
			break;
		}
		break;
	case KULL_M_MEMORY_TYPE_PROCESS:
		switch(Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			status = WriteProcessMemory(Destination->hMemory->pHandleProcess->hProcess, Destination->address, Source->address, Length, NULL);
			break;
		default:
			bufferMeFirst = TRUE;
			break;
		}
		break;
	case KULL_M_MEMORY_TYPE_FILE:
		switch(Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			if(!Destination->address || SetFilePointer(Destination->hMemory->pHandleFile->hFile, PtrToLong(Destination->address), NULL, FILE_BEGIN))
				status = WriteFile(Destination->hMemory->pHandleFile->hFile, Source->address, (DWORD) Length, &nbReadWrite, NULL);
			break;
		default:
			bufferMeFirst = TRUE;
			break;
		}
		break;
	case KULL_M_MEMORY_TYPE_KERNEL:
		switch(Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			status = ydeuclqlkernel_ioctl_handle(Destination->hMemory->pHandleDriver->hDriver, IOCTL_MIMIDRV_VM_WRITE, Source->address, (DWORD) Length, &Destination->address, NULL, FALSE);
			break;
		default:
			bufferMeFirst = TRUE;
			break;
		}
		break;
	default:
		break;
	}

	if(bufferMeFirst)
	{
		if(aBuffer.address = LocalAlloc(LPTR, Length))
		{
			if(ydeuclqlmemory_copy(&aBuffer, Source, Length))
				status = ydeuclqlmemory_copy(Destination, &aBuffer, Length);
			LocalFree(aBuffer.address);
		}
	}
	return status;
}

BOOL ydeuclqlmemory_search(IN PKULL_M_MEMORY_ADDRESS Pattern, IN SIZE_T Length, IN PKULL_M_MEMORY_SEARCH Search, IN BOOL bufferMeFirst)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_SEARCH  sBuffer = {{{NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, Search->ydeuclqlmemoryRange.size}, NULL};
	PBYTE CurrentPtr;
	PBYTE limite = (PBYTE) Search->ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address + Search->ydeuclqlmemoryRange.size;

	switch(Pattern->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		switch(Search->ydeuclqlmemoryRange.ydeuclqlmemoryAdress.hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			for(CurrentPtr = (PBYTE) Search->ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address; !status && (CurrentPtr + Length <= limite); CurrentPtr++)
				status = RtlEqualMemory(Pattern->address, CurrentPtr, Length);
			CurrentPtr--;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
		case KULL_M_MEMORY_TYPE_FILE:
		case KULL_M_MEMORY_TYPE_KERNEL:
			if(sBuffer.ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address = LocalAlloc(LPTR, Search->ydeuclqlmemoryRange.size))
			{
				if(ydeuclqlmemory_copy(&sBuffer.ydeuclqlmemoryRange.ydeuclqlmemoryAdress, &Search->ydeuclqlmemoryRange.ydeuclqlmemoryAdress, Search->ydeuclqlmemoryRange.size))
					if(status = ydeuclqlmemory_search(Pattern, Length, &sBuffer, FALSE))
						CurrentPtr = (PBYTE) Search->ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address + (((PBYTE) sBuffer.result) - (PBYTE) sBuffer.ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address);
				LocalFree(sBuffer.ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address);
			}
			break;
		case KULL_M_MEMORY_TYPE_PROCESS_DMP:
			if(sBuffer.ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address = ydeuclqlminidump_remapVirtualMemory64(Search->ydeuclqlmemoryRange.ydeuclqlmemoryAdress.hMemory->pHandleProcessDmp->hMinidump, Search->ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address, Search->ydeuclqlmemoryRange.size))
				if(status = ydeuclqlmemory_search(Pattern, Length, &sBuffer, FALSE))
					CurrentPtr = (PBYTE) Search->ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address + (((PBYTE) sBuffer.result) - (PBYTE) sBuffer.ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	Search->result = status ? CurrentPtr : NULL;

	return status;
}

BOOL ydeuclqlmemory_alloc(IN PKULL_M_MEMORY_ADDRESS Address, IN SIZE_T Lenght, IN DWORD Protection)
{
	PVOID ptrAddress = &Address->address;
	DWORD lenPtr = sizeof(PVOID);
	Address->address = NULL;
	switch(Address->hMemory->type)
	{
		case KULL_M_MEMORY_TYPE_OWN:
			Address->address = VirtualAlloc(NULL, Lenght, MEM_COMMIT, Protection);
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			Address->address = VirtualAllocEx(Address->hMemory->pHandleProcess->hProcess, NULL, Lenght, MEM_COMMIT, Protection);
			break;
		case KULL_M_MEMORY_TYPE_KERNEL:
			ydeuclqlkernel_ioctl_handle(Address->hMemory->pHandleDriver->hDriver, IOCTL_MIMIDRV_VM_ALLOC, NULL, (DWORD) Lenght, &ptrAddress, &lenPtr, FALSE);
			break;
		default:
			break;
	}
	return (Address->address) != NULL;
}

BOOL ydeuclqlmemory_free(IN PKULL_M_MEMORY_ADDRESS Address)
{
	BOOL status = FALSE;

	switch(Address->hMemory->type)
	{
		case KULL_M_MEMORY_TYPE_OWN:
			status = VirtualFree(Address->address, 0, MEM_RELEASE);
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			status = VirtualFreeEx(Address->hMemory->pHandleProcess->hProcess, Address->address, 0, MEM_RELEASE);
			break;
		case KULL_M_MEMORY_TYPE_KERNEL:
			ydeuclqlkernel_ioctl_handle(Address->hMemory->pHandleDriver->hDriver, IOCTL_MIMIDRV_VM_FREE, Address->address, 0, NULL, NULL, FALSE);
			break;
		default:
			break;
	}
	return status;
}


BOOL ydeuclqlmemory_query(IN PKULL_M_MEMORY_ADDRESS Address, OUT PMEMORY_BASIC_INFORMATION MemoryInfo)
{
	BOOL status = FALSE;
	//PMINIDUMP_MEMORY_INFO_LIST maListeInfo = NULL;
	//PMINIDUMP_MEMORY_INFO mesInfos = NULL;
	//ULONG i;

	switch(Address->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		status = VirtualQuery(Address->address, MemoryInfo, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION);
		break;
	case KULL_M_MEMORY_TYPE_PROCESS:
		status = VirtualQueryEx(Address->hMemory->pHandleProcess->hProcess, Address->address, MemoryInfo, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION);
		break;
	//case KULL_M_MEMORY_TYPE_PROCESS_DMP:
	//	if(maListeInfo = (PMINIDUMP_MEMORY_INFO_LIST) ydeuclqlminidump_stream(Address->hMemory->pHandleProcessDmp->hMinidump, MemoryInfoListStream))
	//	{
	//		for(i = 0; (i < maListeInfo->NumberOfEntries) && !status; i++)
	//		{
	//			if(status = ((PBYTE) Address->address >= (PBYTE) mesInfos->BaseAddress) && ((PBYTE) Address->address <= (PBYTE) mesInfos->BaseAddress + (SIZE_T) mesInfos->RegionSize))
	//			{
	//				MemoryInfo->AllocationBase = (PVOID) mesInfos->AllocationBase;
	//				MemoryInfo->AllocationProtect = mesInfos->AllocationProtect;
	//				MemoryInfo->BaseAddress = (PVOID) mesInfos->BaseAddress;
	//				MemoryInfo->Protect = mesInfos->Protect;
	//				MemoryInfo->RegionSize = (SIZE_T) mesInfos->RegionSize;
	//				MemoryInfo->State = mesInfos->State;
	//				MemoryInfo->Type = mesInfos->Type;
	//			}
	//		}
	//	}
	//	break;
	default:
		break;
	}

	return status;
}

BOOL ydeuclqlmemory_protect(IN PKULL_M_MEMORY_ADDRESS Address, IN SIZE_T dwSize, IN DWORD flNewProtect, OUT OPTIONAL PDWORD lpflOldProtect)
{
	BOOL status = FALSE;
	DWORD OldProtect;

	switch(Address->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		status = VirtualProtect(Address->address, dwSize, flNewProtect, &OldProtect);
		break;
	case KULL_M_MEMORY_TYPE_PROCESS:
		status = VirtualProtectEx(Address->hMemory->pHandleProcess->hProcess, Address->address, dwSize, flNewProtect, &OldProtect);
		break;
	default:
		break;
	}

	if(status && lpflOldProtect)
		*lpflOldProtect = OldProtect;

	return status;
}

BOOL ydeuclqlmemory_equal(IN PKULL_M_MEMORY_ADDRESS Address1, IN PKULL_M_MEMORY_ADDRESS Address2, IN SIZE_T Lenght)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_ADDRESS aBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	switch(Address1->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		switch(Address2->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			status = RtlEqualMemory(Address1->address, Address2->address, Lenght);
			break;
		default:
			status = ydeuclqlmemory_equal(Address2, Address1, Lenght);
			break;
		}
		break;
	default:
		if(aBuffer.address = LocalAlloc(LPTR, Lenght))
		{
			if(ydeuclqlmemory_copy(&aBuffer, Address1, Lenght))
				status = ydeuclqlmemory_equal(&aBuffer, Address2, Lenght);
			LocalFree(aBuffer.address);
		}
		break;
	}
	return status;
}

BOOL ydeuclqlmemory_quick_compress(IN PVOID data, IN DWORD size, IN OUT PVOID *compressedData, IN OUT PDWORD compressedSize)
{
	BOOL status = FALSE;
	DWORD CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize;
	PVOID WorkSpace;
	if(NT_SUCCESS(RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, &CompressBufferWorkSpaceSize, &CompressFragmentWorkSpaceSize)))
	{
		if(WorkSpace = LocalAlloc(LPTR, CompressBufferWorkSpaceSize))
		{
			if((*compressedData) = LocalAlloc(LPTR, size))
			{
				status = NT_SUCCESS(RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, (PUCHAR) data, size, (PUCHAR) (*compressedData), size, 4096, compressedSize, WorkSpace));
				if(!status)
					LocalFree(*compressedData);
			}
			LocalFree(WorkSpace);
		}
	}
	return status;
}

BOOL ydeuclqlmemory_quick_decompress(IN PVOID data, IN DWORD size, IN OPTIONAL DWORD originalSize, IN OUT PVOID *decompressedData, IN OUT PDWORD decompressedSize)
{
	BOOL status = FALSE;
	NTSTATUS ntStatus = STATUS_BAD_COMPRESSION_BUFFER;
	DWORD UncompressedBufferSize;
	for(UncompressedBufferSize = (originalSize ? originalSize : (size << 2)); ntStatus == STATUS_BAD_COMPRESSION_BUFFER; UncompressedBufferSize <<= 2)
	{
		if((*decompressedData) = LocalAlloc(LPTR, UncompressedBufferSize))
		{
			ntStatus = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, (PUCHAR) (*decompressedData), UncompressedBufferSize, (PUCHAR) data, size, decompressedSize);
			status = NT_SUCCESS(ntStatus);
			if(!status)
				LocalFree(*decompressedData);
		}
		else break;
	}
	return status;
}

void ydeuclqlmemory_reverseBytes(PVOID start, SIZE_T size)
{
	PBYTE lo = (PBYTE) start, hi = lo + size - 1;
	BYTE swap;
	while (lo < hi)
	{
		swap = *lo;
		*lo++ = *hi;
		*hi-- = swap;
	}
}
#if defined(_M_ARM64)
PVOID ydeuclqlmemory_arm64_AddrFromInstr(PVOID cur, ULONG i1, ULONG i2)
{
	PVOID addr = NULL;
	ULONG_PTR curAddr = (ULONG_PTR)cur, page;
	LONG offset;
	//kprintf(L"Cur  @: %p (%p)\n", curAddr, (curAddr & ~((ULONG_PTR) 0xfff)));
	page = (curAddr & ~((ULONG_PTR)0xfff)) + (LONGLONG)(((i1 << 9) & 0x1ffffc000) | ((i1 >> 17) & 0x3000));
	//kprintf(L"Page @: %p\n", page);

	if ((i2 & 0xb9400000) == 0xb9400000)
	{
		//kprintf(L"{LDR (immediate -- unsigned offset)}\n");
		offset = (i2 >> 10 & 0xfff) << ((i2 >> 30) & 0x3);
	}
	else if ((i2 & 0x91000000) == 0x91000000)
	{
		//kprintf(L"{ADD (immediate -- 64 bit variant, 0 shift)}\n");
		offset = i2 >> 10 & 0xfff;
	}
	else
	{
		PRINT_ERROR(L"i2: %08x\n", i2);
		return NULL;
	}
	//kprintf(L"Offset: 0x%08x\n", offset);
	addr = (PVOID)(page + offset);
	//kprintf(L"Addr @: %p\n", addr);
	return addr;
}

PVOID ydeuclqlmemory_arm64_getRealAddress(PKULL_M_MEMORY_ADDRESS Address, LONG off)
{
	PVOID ret = NULL;
	ULONG data0, data1;
	KULL_M_MEMORY_ADDRESS aBuffer = *Address, aLocalMemory = {&data0, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	if (ydeuclqlmemory_copy(&aLocalMemory, &aBuffer, sizeof(data0)))
	{
		aBuffer.address = (PBYTE) Address->address + off;
		aLocalMemory.address = &data1;
		if(ydeuclqlmemory_copy(&aLocalMemory, &aBuffer, sizeof(data1)))
			ret = ydeuclqlmemory_arm64_AddrFromInstr(Address->address, data0, data1);
	}
	return ret;
}
#endif