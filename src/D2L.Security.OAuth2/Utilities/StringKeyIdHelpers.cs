using System;

namespace D2L.Security.OAuth2.Utilities {
	internal static class StringKeyIdHelpers {
		public static bool KeyIdEquals( this string x, string keyId ) {
			return string.Equals( x, keyId, StringComparison.Ordinal );
		}
	}
}
