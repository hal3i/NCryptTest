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

		EXPECT_EQ(ERROR_SUCCESS, actual) << "Already created";
		EXPECT_EQ(ERROR_SUCCESS, sut.FreeObject(hKey));
		ASSERT_EQ(ERROR_SUCCESS, sut.FreeResource());
	}

	TEST(NCryptTest, FinalizeAndDeleteKey_ShouldBeReturned_ERROR_SUCCESS) {
		LPCWSTR pxzKeyName = L"ncrypt_test_key_name";
		NCRYPT_KEY_HANDLE hKey = 0;
		NCrypt sut;
		ASSERT_EQ(ERROR_SUCCESS, sut.OpenStorageProvider(MS_KEY_STORAGE_PROVIDER));
		ASSERT_EQ(ERROR_SUCCESS, sut.CreatePersistedKey(&hKey, BCRYPT_ECDH_P256_ALGORITHM, pxzKeyName, 0, 0)) << "Already created";

		SECURITY_STATUS actual1 = sut.FinalizeKey(hKey, 0);
		SECURITY_STATUS actual2 = sut.DeleteKey(pxzKeyName, 0);

		EXPECT_EQ(ERROR_SUCCESS, actual1);
		EXPECT_EQ(ERROR_SUCCESS, actual2);
		ASSERT_EQ(ERROR_SUCCESS, sut.FreeResource());
	}
}
