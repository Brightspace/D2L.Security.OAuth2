using System;
using System.Net;

namespace D2L.Security.OAuth2.Provisioning {
	internal static class ProvisioningConstants {

		internal static class AssertionGrant {
			internal const string AUDIENCE = "https://api.brightspace.com/auth/token";
			internal static readonly string GRANT_TYPE =
				WebUtility.UrlEncode( "urn:ietf:params:oauth:grant-type:jwt-bearer" );
			internal static readonly TimeSpan ASSERTION_TOKEN_LIFETIME = TimeSpan.FromMinutes( 30 );
			internal const string KEY_ID_NAME = "kid";
		}

	}
}
