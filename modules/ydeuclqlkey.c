/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "ydeuclqlkey.h"

PKULL_M_KEY_CAPI_BLOB ydeuclqlkey_capi_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_KEY_CAPI_BLOB capiKey = NULL;
	if(capiKey = (PKULL_M_KEY_CAPI_BLOB) LocalAlloc(LPTR, sizeof(KULL_M_KEY_CAPI_BLOB)))
	{
		RtlCopyMemory(capiKey, data, FIELD_OFFSET(KULL_M_KEY_CAPI_BLOB, pName));
		capiKey->pName = (PSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_KEY_CAPI_BLOB, pName));
		capiKey->pHash = (PBYTE) capiKey->pName + capiKey->dwNameLen;
		capiKey->pSiPublicKey = (PBYTE) capiKey->pHash + capiKey->dwHashLen;
		capiKey->pSiPrivateKey = (PBYTE) capiKey->pSiPublicKey + capiKey->dwSiPublicKeyLen;
		capiKey->pSiExportFlag = (PBYTE) capiKey->pSiPrivateKey + capiKey->dwSiPrivateKeyLen;
		capiKey->pExPublicKey = (PBYTE) capiKey->pSiExportFlag + capiKey->dwSiExportFlagLen;
		capiKey->pExPrivateKey = (PBYTE) capiKey->pExPublicKey + capiKey->dwExPublicKeyLen;
		capiKey->pExExportFlag = (PBYTE) capiKey->pExPrivateKey + capiKey->dwExPrivateKeyLen;

		ydeuclqlstring_ptr_replace(&capiKey->pName, capiKey->dwNameLen);
		ydeuclqlstring_ptr_replace(&capiKey->pHash, capiKey->dwHashLen);
		ydeuclqlstring_ptr_replace(&capiKey->pSiPublicKey, capiKey->dwSiPublicKeyLen);
		ydeuclqlstring_ptr_replace(&capiKey->pSiPrivateKey, capiKey->dwSiPrivateKeyLen);
		ydeuclqlstring_ptr_replace(&capiKey->pSiExportFlag, capiKey->dwSiExportFlagLen);
		ydeuclqlstring_ptr_replace(&capiKey->pExPublicKey, capiKey->dwExPublicKeyLen);
		ydeuclqlstring_ptr_replace(&capiKey->pExPrivateKey, capiKey->dwExPrivateKeyLen);
		ydeuclqlstring_ptr_replace(&capiKey->pExExportFlag, capiKey->dwExExportFlagLen);
	}
	return capiKey;
}

void ydeuclqlkey_capi_delete(PKULL_M_KEY_CAPI_BLOB capiKey)
{
	if(capiKey)
	{
		if(capiKey->pName)
			LocalFree(capiKey->pName);
		if(capiKey->pHash)
			LocalFree(capiKey->pHash);
		if(capiKey->pSiPublicKey)
			LocalFree(capiKey->pSiPublicKey);
		if(capiKey->pSiPrivateKey)
			LocalFree(capiKey->pSiPrivateKey);
		if(capiKey->pSiExportFlag)
			LocalFree(capiKey->pSiExportFlag);
		if(capiKey->pExPublicKey)
			LocalFree(capiKey->pExPublicKey);
		if(capiKey->pExPrivateKey)
			LocalFree(capiKey->pExPrivateKey);
		if(capiKey->pExExportFlag)
			LocalFree(capiKey->pExExportFlag);
		LocalFree(capiKey);
	}
}

void ydeuclqlkey_capi_descr(DWORD level, PKULL_M_KEY_CAPI_BLOB capiKey)
{
	kprintf(L"%*s" L"**KEY (capi)**\n", level << 1, L"");
	if(capiKey)
	{
		kprintf(L"%*s" L"  dwVersion          : %08x - %u\n", level << 1, L"", capiKey->dwVersion, capiKey->dwVersion);
		kprintf(L"%*s" L"  dwUniqueNameLen    : %08x - %u\n", level << 1, L"", capiKey->dwNameLen, capiKey->dwNameLen);
		kprintf(L"%*s" L"  dwSiPublicKeyLen   : %08x - %u\n", level << 1, L"", capiKey->dwSiPublicKeyLen, capiKey->dwSiPublicKeyLen);
		kprintf(L"%*s" L"  dwSiPrivateKeyLen  : %08x - %u\n", level << 1, L"", capiKey->dwSiPrivateKeyLen, capiKey->dwSiPrivateKeyLen);
		kprintf(L"%*s" L"  dwExPublicKeyLen   : %08x - %u\n", level << 1, L"", capiKey->dwExPublicKeyLen, capiKey->dwExPublicKeyLen);
		kprintf(L"%*s" L"  dwExPrivateKeyLen  : %08x - %u\n", level << 1, L"", capiKey->dwExPrivateKeyLen, capiKey->dwExPrivateKeyLen);
		kprintf(L"%*s" L"  dwHashLen          : %08x - %u\n", level << 1, L"", capiKey->dwHashLen, capiKey->dwHashLen);
		kprintf(L"%*s" L"  dwSiExportFlagLen  : %08x - %u\n", level << 1, L"", capiKey->dwSiExportFlagLen, capiKey->dwSiExportFlagLen);
		kprintf(L"%*s" L"  dwExExportFlagLen  : %08x - %u\n", level << 1, L"", capiKey->dwExExportFlagLen, capiKey->dwExExportFlagLen);


		kprintf(L"%*s" L"  pUniqueName        : ", level << 1, L""); kprintf(L"%S\n", capiKey->pName);
		kprintf(L"%*s" L"  pHash              : ", level << 1, L""); ydeuclqlstring_wprintf_hex(capiKey->pHash, capiKey->dwHashLen, 0); kprintf(L"\n");
		kprintf(L"%*s" L"  pSiPublicKey       : ", level << 1, L""); ydeuclqlstring_wprintf_hex(capiKey->pSiPublicKey, capiKey->dwSiPublicKeyLen, 0); kprintf(L"\n");
		kprintf(L"%*s" L"  pSiPrivateKey      :\n", level << 1, L"");
		if(capiKey->pSiPrivateKey && capiKey->dwSiPrivateKeyLen)
			ydeuclqldpapi_blob_quick_descr(level + 1, capiKey->pSiPrivateKey); /*ydeuclqlstring_wprintf_hex(capiKey->pPrivateKey, capiKey->dwPrivateKeyLen, 0);*/
		kprintf(L"%*s" L"  pSiExportFlag      :\n", level << 1, L"");
		if(capiKey->pSiExportFlag && capiKey->dwSiExportFlagLen)
			ydeuclqldpapi_blob_quick_descr(level + 1, capiKey->pSiExportFlag); /*ydeuclqlstring_wprintf_hex(capiKey->pExportFlag, capiKey->dwExportFlagLen, 0);*/
		kprintf(L"%*s" L"  pExPublicKey       : ", level << 1, L""); ydeuclqlstring_wprintf_hex(capiKey->pExPublicKey, capiKey->dwExPublicKeyLen, 0); kprintf(L"\n");
		kprintf(L"%*s" L"  pExPrivateKey      :\n", level << 1, L"");
		if(capiKey->pExPrivateKey && capiKey->dwExPrivateKeyLen)
			ydeuclqldpapi_blob_quick_descr(level + 1, capiKey->pExPrivateKey); /*ydeuclqlstring_wprintf_hex(capiKey->pPrivateKey, capiKey->dwPrivateKeyLen, 0);*/
		kprintf(L"%*s" L"  pExExportFlag      :\n", level << 1, L"");
		if(capiKey->pExExportFlag && capiKey->dwExExportFlagLen)
			ydeuclqldpapi_blob_quick_descr(level + 1, capiKey->pExExportFlag); /*ydeuclqlstring_wprintf_hex(capiKey->pExportFlag, capiKey->dwExportFlagLen, 0);*/

	}
}

BOOL ydeuclqlkey_capi_write(PKULL_M_KEY_CAPI_BLOB capiKey, PVOID *data, DWORD *size)
{
	BOOL status = FALSE;
	PBYTE ptr;
	*size = FIELD_OFFSET(KULL_M_KEY_CAPI_BLOB, pName) + capiKey->dwNameLen + capiKey->dwHashLen + capiKey->dwSiPublicKeyLen + capiKey->dwSiPrivateKeyLen + capiKey->dwSiExportFlagLen + capiKey->dwExPublicKeyLen + capiKey->dwExPrivateKeyLen + capiKey->dwExExportFlagLen;
	if(*data = LocalAlloc(LPTR, *size))
	{
		ptr = (PBYTE) *data;
		RtlCopyMemory(ptr, capiKey, FIELD_OFFSET(KULL_M_KEY_CAPI_BLOB, pName));
		ptr += FIELD_OFFSET(KULL_M_KEY_CAPI_BLOB, pName);
		RtlCopyMemory(ptr, capiKey->pName, capiKey->dwNameLen);
		ptr += capiKey->dwNameLen;
		RtlCopyMemory(ptr, capiKey->pHash, capiKey->dwHashLen);
		ptr += capiKey->dwHashLen;
		RtlCopyMemory(ptr, capiKey->pSiPublicKey, capiKey->dwSiPublicKeyLen);
		ptr += capiKey->dwSiPublicKeyLen;
		RtlCopyMemory(ptr, capiKey->pSiPrivateKey, capiKey->dwSiPrivateKeyLen);
		ptr += capiKey->dwSiPrivateKeyLen;
		RtlCopyMemory(ptr, capiKey->pSiExportFlag, capiKey->dwSiExportFlagLen);
		ptr += capiKey->dwSiExportFlagLen;
		RtlCopyMemory(ptr, capiKey->pExPublicKey, capiKey->dwExPublicKeyLen);
		ptr += capiKey->dwExPublicKeyLen;
		RtlCopyMemory(ptr, capiKey->pExPrivateKey, capiKey->dwExPrivateKeyLen);
		ptr += capiKey->dwExPrivateKeyLen;
		RtlCopyMemory(ptr, capiKey->pExExportFlag, capiKey->dwExExportFlagLen);
		status = TRUE;
	}
	return status;
}

BOOL ydeuclqlkey_capi_decryptedkey_to_raw(LPCVOID publickey, DWORD publickeyLen, LPCVOID decrypted, DWORD decryptedLen, ALG_ID keyAlg, PRSA_GENERICKEY_BLOB *blob, DWORD *blobLen, DWORD *dwProviderType)
{
	BOOL status = FALSE;
	DWORD keyLen;
	PBYTE ptrDestination, ptrSource;

	if(((PDWORD) decrypted)[0] == '2ASR')
	{
		keyLen = ((PDWORD) decrypted)[2];
		*blobLen = sizeof(RSA_GENERICKEY_BLOB) + ((keyLen * 9) / 16);
		if(*blob = (PRSA_GENERICKEY_BLOB) LocalAlloc(LPTR, *blobLen))
		{
			status = TRUE;
			(*blob)->Header.bType = PRIVATEKEYBLOB;
			(*blob)->Header.bVersion = CUR_BLOB_VERSION;
			(*blob)->Header.reserved = 0;
			(*blob)->Header.aiKeyAlg = keyAlg;

			(*blob)->RsaKey.magic = ((PDWORD) decrypted)[0];
			(*blob)->RsaKey.bitlen = keyLen;
			(*blob)->RsaKey.pubexp = ((PDWORD) decrypted)[4];

			ptrDestination = ((PBYTE) (*blob)) + sizeof(RSA_GENERICKEY_BLOB);
			ptrSource = (PBYTE) ((PDWORD) decrypted + 5);

			RtlCopyMemory(ptrDestination, ptrSource, keyLen / 8);
			ptrDestination += keyLen / 8;
			ptrSource += (keyLen / 8) + 8;
			RtlCopyMemory(ptrDestination, ptrSource, keyLen / 16);
			ptrDestination += keyLen / 16;
			ptrSource += (keyLen / 16) + 4;
			RtlCopyMemory(ptrDestination, ptrSource, keyLen / 16);
			ptrDestination += keyLen / 16;
			ptrSource += (keyLen / 16) + 4;
			RtlCopyMemory(ptrDestination, ptrSource, keyLen / 16);
			ptrDestination += keyLen / 16;
			ptrSource += (keyLen / 16) + 4;
			RtlCopyMemory(ptrDestination, ptrSource, keyLen / 16);
			ptrDestination += keyLen / 16;
			ptrSource += (keyLen / 16) + 4;
			RtlCopyMemory(ptrDestination, ptrSource, keyLen / 16);
			ptrDestination += keyLen / 16;
			ptrSource += (keyLen / 16) + 4;
			RtlCopyMemory(ptrDestination, ptrSource, keyLen / 8);

			*dwProviderType = PROV_RSA_FULL;
		}
	}
	else
	{
		if(publickey && publickeyLen)
		{
			if((((PDSS_GENERICKEY3_BLOB) publickey)->Header.bType == PRIVATEKEYBLOB) && (((PDSS_GENERICKEY3_BLOB) publickey)->Header.bVersion == (CUR_BLOB_VERSION + 1)) && (((PDSS_GENERICKEY3_BLOB) publickey)->DsaKey.magic == '4SSD'))
			{
				*blobLen = publickeyLen + decryptedLen;
				if(*blob = (PRSA_GENERICKEY_BLOB) LocalAlloc(LPTR, *blobLen))
				{
					status = TRUE;
					RtlCopyMemory(*blob, publickey, publickeyLen);
					RtlCopyMemory(((PBYTE) *blob) + publickeyLen, decrypted, decryptedLen);
					((PDSS_GENERICKEY3_BLOB) *blob)->DsaKey.bitlenX = decryptedLen * 8;
					*dwProviderType = PROV_DSS;
				}
			}
		}
	}
	return status;
}

PKULL_M_KEY_CNG_BLOB ydeuclqlkey_cng_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_KEY_CNG_BLOB cngKey = NULL;

	if(cngKey = (PKULL_M_KEY_CNG_BLOB) LocalAlloc(LPTR, sizeof(KULL_M_KEY_CNG_BLOB)))
	{
		RtlCopyMemory(cngKey, data, FIELD_OFFSET(KULL_M_KEY_CNG_BLOB, pName));
		cngKey->pName = (PSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_KEY_CNG_BLOB, pName));
		if(!ydeuclqlkey_cng_properties_create((PBYTE) cngKey->pName + cngKey->dwNameLen, cngKey->dwPublicPropertiesLen, &cngKey->pPublicProperties, &cngKey->cbPublicProperties))
			PRINT_ERROR(L"ydeuclqlkey_cng_properties_create (public)\n");
		cngKey->pPrivateProperties = (PBYTE) cngKey->pName + cngKey->dwNameLen + cngKey->dwPublicPropertiesLen;
		cngKey->pPrivateKey = (PBYTE) cngKey->pPrivateProperties + cngKey->dwPrivatePropertiesLen;
		ydeuclqlstring_ptr_replace(&cngKey->pName, cngKey->dwNameLen);
		ydeuclqlstring_ptr_replace(&cngKey->pPrivateProperties, cngKey->dwPrivatePropertiesLen);
		ydeuclqlstring_ptr_replace(&cngKey->pPrivateKey, cngKey->dwPrivateKeyLen);
	}
	return cngKey;
}

void ydeuclqlkey_cng_delete(PKULL_M_KEY_CNG_BLOB cngKey)
{
	if(cngKey)
	{
		if(cngKey->pName)
			LocalFree(cngKey->pName);
		if(cngKey->cbPublicProperties && cngKey->pPublicProperties)
			ydeuclqlkey_cng_properties_delete(cngKey->pPublicProperties, cngKey->cbPublicProperties);
		if(cngKey->pPrivateProperties)
			LocalFree(cngKey->pPrivateProperties);
		if(cngKey->pPrivateKey)
			LocalFree(cngKey->pPrivateKey);
		LocalFree(cngKey);
	}
}

void ydeuclqlkey_cng_descr(DWORD level, PKULL_M_KEY_CNG_BLOB cngKey)
{
	kprintf(L"%*s" L"**KEY (cng)**\n", level << 1, L"");
	if(cngKey)
	{
		kprintf(L"%*s" L"  dwVersion             : %08x - %u\n", level << 1, L"", cngKey->dwVersion, cngKey->dwVersion);
		kprintf(L"%*s" L"  unk                   : %08x - %u\n", level << 1, L"", cngKey->unk, cngKey->unk);
		kprintf(L"%*s" L"  dwNameLen             : %08x - %u\n", level << 1, L"", cngKey->dwNameLen, cngKey->dwNameLen);
		kprintf(L"%*s" L"  type                  : %08x - %u\n", level << 1, L"", cngKey->type, cngKey->type);
		kprintf(L"%*s" L"  dwPublicPropertiesLen : %08x - %u\n", level << 1, L"", cngKey->dwPublicPropertiesLen, cngKey->dwPublicPropertiesLen);
		kprintf(L"%*s" L"  dwPrivatePropertiesLen: %08x - %u\n", level << 1, L"", cngKey->dwPrivatePropertiesLen, cngKey->dwPrivatePropertiesLen);
		kprintf(L"%*s" L"  dwPrivateKeyLen       : %08x - %u\n", level << 1, L"", cngKey->dwPrivateKeyLen, cngKey->dwPrivateKeyLen);
		kprintf(L"%*s" L"  unkArray[16]          : ", level << 1, L""); ydeuclqlstring_wprintf_hex(cngKey->unkArray, sizeof(cngKey->unkArray), 0); kprintf(L"\n");
		kprintf(L"%*s" L"  pName                 : ", level << 1, L""); kprintf(L"%.*s\n", cngKey->dwNameLen / sizeof(wchar_t), cngKey->pName);
		kprintf(L"%*s" L"  pPublicProperties     : ", level << 1, L""); ydeuclqlkey_cng_properties_descr(level + 1, cngKey->pPublicProperties, cngKey->cbPublicProperties);
		kprintf(L"%*s" L"  pPrivateProperties    :\n", level << 1, L"");
		if(cngKey->pPrivateProperties && cngKey->dwPrivatePropertiesLen)
			ydeuclqldpapi_blob_quick_descr(level + 1, cngKey->pPrivateProperties); /*ydeuclqlstring_wprintf_hex(cngKey->pPrivateProperties, cngKey->dwPrivatePropertiesLen, 0);*/
		kprintf(L"%*s" L"  pPrivateKey           :\n", level << 1, L"");
		if(cngKey->pPrivateKey && cngKey->dwPrivateKeyLen)
			ydeuclqldpapi_blob_quick_descr(level + 1, cngKey->pPrivateKey); /*ydeuclqlstring_wprintf_hex(cngKey->pPrivateKey, cngKey->dwPrivateKeyLen, 0);*/
	}
}

PKULL_M_KEY_CNG_PROPERTY ydeuclqlkey_cng_property_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_KEY_CNG_PROPERTY cngProperty = NULL;
	if(cngProperty = (PKULL_M_KEY_CNG_PROPERTY) LocalAlloc(LPTR, sizeof(KULL_M_KEY_CNG_PROPERTY)))
	{
		RtlCopyMemory(cngProperty, data, FIELD_OFFSET(KULL_M_KEY_CNG_PROPERTY, pName));
		cngProperty->pName = (PSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_KEY_CNG_PROPERTY, pName));
		cngProperty->pProperty = (PBYTE) cngProperty->pName + cngProperty->dwNameLen;
		ydeuclqlstring_ptr_replace(&cngProperty->pName, cngProperty->dwNameLen);
		ydeuclqlstring_ptr_replace(&cngProperty->pProperty, cngProperty->dwPropertyLen);
	}
	return cngProperty;
}

void ydeuclqlkey_cng_property_delete(PKULL_M_KEY_CNG_PROPERTY property)
{
	if(property)
	{
		if(property->pName)
			LocalFree(property->pName);
		if(property->pProperty)
			LocalFree(property->pProperty);
		LocalFree(property);
	}
}

void ydeuclqlkey_cng_property_descr(DWORD level, PKULL_M_KEY_CNG_PROPERTY property)
{
	kprintf(L"%*s" L"**KEY CNG PROPERTY**\n", level << 1, L"");
	if(property)
	{
		kprintf(L"%*s" L"  dwStructLen     : %08x - %u\n", level << 1, L"", property->dwStructLen, property->dwStructLen);
		kprintf(L"%*s" L"  type            : %08x - %u\n", level << 1, L"", property->type, property->type);
		kprintf(L"%*s" L"  unk             : %08x - %u\n", level << 1, L"", property->unk, property->unk);
		kprintf(L"%*s" L"  dwNameLen       : %08x - %u\n", level << 1, L"", property->dwNameLen, property->dwNameLen);
		kprintf(L"%*s" L"  dwPropertyLen   : %08x - %u\n", level << 1, L"", property->dwPropertyLen, property->dwPropertyLen);
		kprintf(L"%*s" L"  pName           : ", level << 1, L""); kprintf(L"%.*s\n", property->dwNameLen / sizeof(wchar_t), property->pName);
		kprintf(L"%*s" L"  pProperty       : ", level << 1, L""); ydeuclqlstring_wprintf_hex(property->pProperty, property->dwPropertyLen, 0); kprintf(L"\n\n");
	}
}

BOOL ydeuclqlkey_cng_properties_create(PVOID data, DWORD size, PKULL_M_KEY_CNG_PROPERTY **properties, DWORD *count)
{
	BOOL status = FALSE;
	DWORD i, j;

	for(i = 0, *count = 0; i < size; i += ((PKULL_M_KEY_CNG_PROPERTY) ((PBYTE) data + i))->dwStructLen, (*count)++);

	if((*properties) = (PKULL_M_KEY_CNG_PROPERTY *) LocalAlloc(LPTR, *count * sizeof(PKULL_M_KEY_CNG_PROPERTY)))
	{
		for(i = 0, j = 0, status = TRUE; (i < (*count)) && status; i++)
		{
			if((*properties)[i] = ydeuclqlkey_cng_property_create((PBYTE) data + j))
				j +=  (*properties)[i]->dwStructLen;
			else status = FALSE;
		}
	}
	if(!status)
	{
		ydeuclqlkey_cng_properties_delete(*properties, *count);
		*properties = NULL;
		*count = 0;
	}
	return status;
}

void ydeuclqlkey_cng_properties_delete(PKULL_M_KEY_CNG_PROPERTY *properties, DWORD count)
{
	DWORD i;
	if(properties)
	{
		for(i = 0; i < count; i++)
			ydeuclqlkey_cng_property_delete(properties[i]);
		LocalFree(properties);
	}
}

void ydeuclqlkey_cng_properties_descr(DWORD level, PKULL_M_KEY_CNG_PROPERTY *properties, DWORD count)
{
	DWORD i;
	if(count && properties)
	{
		kprintf(L"%u field(s)\n", count);
		for(i = 0; i < count; i++)
			ydeuclqlkey_cng_property_descr(level, properties[i]);
	}
}