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
}
