#include "pch.h"
#include "NCrypt.h"

SECURITY_STATUS NCrypt::DeleteKey(LPCWSTR pxzKeyName, DWORD dwFlags)
{
	NCryptKeyName* pKeyName;
	PVOID pEnumState = NULL;

	while (NCryptEnumKeys(_hProvider, NULL, &pKeyName, &pEnumState, 0) == ERROR_SUCCESS) {
		if (wcscmp(pKeyName->pszName, pxzKeyName) != 0) {
			NCryptFreeBuffer(pKeyName);
			continue;
		}

		NCRYPT_KEY_HANDLE hKey;
		SECURITY_STATUS status = OpenKey(&hKey, pKeyName->pszName, 0, 0);
		if (status != ERROR_SUCCESS) {
			continue;
		}
		status = NCryptDeleteKey(hKey, dwFlags);
		if (status != ERROR_SUCCESS) {
			NCryptFreeObject(hKey);
			continue;
		}
		break;
	}
	return NCryptFreeBuffer(pEnumState);
}

SECURITY_STATUS NCrypt::ExportKey(NCRYPT_KEY_HANDLE hKey, NCRYPT_KEY_HANDLE hExportKey, LPCWSTR pszBlobType, NCryptBufferDesc *pParameterList, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags)
{
	SECURITY_STATUS status = NCryptExportKey(hKey, hExportKey, pszBlobType, pParameterList, pbOutput, cbOutput, pcbResult, dwFlags);

	return status;
}

SECURITY_STATUS NCrypt::FinalizeKey(NCRYPT_KEY_HANDLE hKey, DWORD dwFlags)
{
	return NCryptFinalizeKey(hKey, dwFlags);
}

SECURITY_STATUS NCrypt::FreeBuffer(PVOID pvInput)
{
	return NCryptFreeBuffer(pvInput);
}

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

SECURITY_STATUS NCrypt::OpenKey(NCRYPT_KEY_HANDLE *phKey, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags)
{
	return NCryptOpenKey(_hProvider, phKey, pszKeyName, dwLegacyKeySpec, dwFlags);
}

SECURITY_STATUS NCrypt::OpenStorageProvider(LPCWSTR pszProviderName)
{
	return NCryptOpenStorageProvider(&_hProvider, MS_KEY_STORAGE_PROVIDER, 0);
}
