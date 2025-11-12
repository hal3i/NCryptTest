#include "pch.h"
#include "NCrypt.h"

SECURITY_STATUS NCrypt::FreeObject(NCRYPT_HANDLE hObject)
{
	return NCryptFreeObject(hObject);
}

SECURITY_STATUS NCrypt::FreeResource()
{
	SECURITY_STATUS status = NTE_INVALID_HANDLE;

	if (_hProvider != NULL) {
		status = FreeObject(_hProvider);
	}

	return status;
}

SECURITY_STATUS NCrypt::CreatePersistedKey(NCRYPT_KEY_HANDLE* phKey, LPCWSTR pszAlgId, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags)
{
	return NCryptCreatePersistedKey(_hProvider, phKey, pszAlgId, pszKeyName, dwLegacyKeySpec, dwFlags);
}

SECURITY_STATUS NCrypt::OpenStorageProvider(LPCWSTR pszProviderName)
{
	return NCryptOpenStorageProvider(&_hProvider, MS_KEY_STORAGE_PROVIDER, 0);
}
