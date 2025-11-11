#include "pch.h"

namespace unittest
{
	TEST(NCryptTest, NCryptOpenStorageProvider_ShouldBeReturned_ERROR_SUCCESS) {
		NCRYPT_PROV_HANDLE hProvider = NULL;

		SECURITY_STATUS actual = NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0);

		ASSERT_EQ(ERROR_SUCCESS, actual);
	}
}
