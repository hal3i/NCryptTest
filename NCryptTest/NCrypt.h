#pragma once

class NCrypt
{
public:
	SECURITY_STATUS CreatePersistedKey(NCRYPT_KEY_HANDLE* phKey, LPCWSTR pszAlgId, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
	SECURITY_STATUS DeleteKey(LPCWSTR pxzKeyName, DWORD dwFlags);
	SECURITY_STATUS ExportKey(NCRYPT_KEY_HANDLE hKey, NCRYPT_KEY_HANDLE hExportKey, LPCWSTR pszBlobType, NCryptBufferDesc* pParameterList, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags);
	SECURITY_STATUS FinalizeKey(NCRYPT_KEY_HANDLE hKey, DWORD dwFlags);
	SECURITY_STATUS FreeBuffer(PVOID pvInput);
	SECURITY_STATUS FreeObject(NCRYPT_HANDLE hObject);
	SECURITY_STATUS FreeResource();
	SECURITY_STATUS OpenKey(NCRYPT_KEY_HANDLE* phKey, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
	SECURITY_STATUS OpenStorageProvider(LPCWSTR pszProviderName);

private:
	NCRYPT_PROV_HANDLE _hProvider = NULL;
};
