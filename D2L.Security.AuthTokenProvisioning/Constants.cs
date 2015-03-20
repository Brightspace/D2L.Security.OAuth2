using System;
using System.Net;

namespace D2L.Security.AuthTokenProvisioning {
	internal static class Constants {

		internal static class Claims {
			internal const string USER = "sub";
			internal const string TENANT_ID = "tenantid";
			internal const string TENANT_URL = "tenanturl";
			internal const string XSRF_TOKEN = "xt";
			internal const string ISSUER = "iss";
		}

		internal static class AssertionGrant {
			internal const string AUDIENCE = "https://api.brightspace.com/auth/token";
			internal static readonly string GRANT_TYPE =
				WebUtility.UrlEncode( "urn:ietf:params:oauth:grant-type:jwt-bearer" );
			internal static readonly TimeSpan ASSERTION_TOKEN_LIFETIME = TimeSpan.FromMinutes( 30 );
			internal const string KEY_ID_NAME = "kid";
		}
	}
}
