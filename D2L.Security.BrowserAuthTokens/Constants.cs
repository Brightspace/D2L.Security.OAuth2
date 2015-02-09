using System;
using System.Net;

namespace D2L.Security.BrowserAuthTokens {
	internal static class Constants {

		internal static readonly TimeSpan ASSERTION_GRANT_JWT_LIFETIME = TimeSpan.FromMinutes( 30 );

		internal static readonly string ASSERTION_GRANT_TYPE =
			WebUtility.UrlEncode( "urn:ietf:params:oauth:grant-type:jwt-bearer" );
	}
}
