using System;

namespace D2L.Security.OAuth2.Utilities {
	internal static class Base64Url {
		public static string Encode( byte[] bytes ) {
			string result = Convert.ToBase64String( bytes );

			result = result
				.Trim( '=' )
				.Replace( '+', '-' )
				.Replace( '/', '_' );

			return result;
		}
	}
}
