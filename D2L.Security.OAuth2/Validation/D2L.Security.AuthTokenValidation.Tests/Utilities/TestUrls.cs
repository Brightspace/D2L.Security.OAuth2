namespace D2L.Security.AuthTokenValidation.Tests.Utilities {
	internal static class TestUrls {

		private const string AUTH_SERVER_SITE = "https://phwinsl01.proddev.d2l:44333";

		internal static readonly string AUTH_TOKEN_PROVISIONING_URL = AUTH_SERVER_SITE + "/core/connect/token";
		internal static readonly string TOKEN_VERIFICATION_AUTHORITY_URL = AUTH_SERVER_SITE + "/core/";
		
		internal static readonly string ISSUER_URL = "https://api.d2l.com/auth";
	}
}
