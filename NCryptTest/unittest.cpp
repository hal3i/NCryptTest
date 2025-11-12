#include "pch.h"
#include "NCrypt.h"

namespace unittest
{
	TEST(NCryptTest, NCryptOpenStorageProvider_ShouldBeReturned_ERROR_SUCCESS) {
		NCrypt sut;

		SECURITY_STATUS actual = sut.OpenStorageProvider(MS_KEY_STORAGE_PROVIDER);

		ASSERT_EQ(ERROR_SUCCESS, actual);
		ASSERT_EQ(ERROR_SUCCESS, sut.FreeResource());
	}

	TEST(NCryptTest, CreatePersistedKey_ShouldBeReturned_ERROR_SUCCESS) {
		NCrypt sut;
		ASSERT_EQ(ERROR_SUCCESS, sut.OpenStorageProvider(MS_KEY_STORAGE_PROVIDER));

		NCRYPT_KEY_HANDLE hKey;
		SECURITY_STATUS actual = sut.CreatePersistedKey(&hKey, BCRYPT_ECDH_P256_ALGORITHM, L"ncrypt_test_key_name", 0, 0);

		ASSERT_EQ(ERROR_SUCCESS, actual) << "Already created";
		ASSERT_EQ(ERROR_SUCCESS, sut.FreeObject(hKey));
		ASSERT_EQ(ERROR_SUCCESS, sut.FreeResource());
	}
}
