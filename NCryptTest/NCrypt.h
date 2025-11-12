#pragma once

class NCrypt
{
public:
	SECURITY_STATUS FreeResource();
	SECURITY_STATUS OpenStorageProvider(LPCWSTR pszProviderName);

private:
	NCRYPT_PROV_HANDLE _hProvider = NULL;
};
