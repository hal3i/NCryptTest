#include "pch.h"
#include "NCrypt.h"

SECURITY_STATUS NCrypt::FreeResource()
{
	SECURITY_STATUS status = NTE_INVALID_HANDLE;

	if (_hProvider != NULL) {
		status = NCryptFreeObject(_hProvider);
	}

	return status;
}

SECURITY_STATUS NCrypt::OpenStorageProvider(LPCWSTR pszProviderName)
{
	return NCryptOpenStorageProvider(&_hProvider, MS_KEY_STORAGE_PROVIDER, 0);
}
