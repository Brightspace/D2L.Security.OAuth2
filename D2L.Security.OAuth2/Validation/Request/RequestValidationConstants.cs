namespace D2L.Security.OAuth2.Validation.Request {
	internal static class RequestValidationConstants {

		internal static class Headers {
			internal const string COOKIE = "Cookie";
			internal const string XSRF = "X-Csrf-Token";
			internal const string AUTHORIZATION = "Authorization";
		}

		internal static class BearerTokens {
			internal const string SCHEME = "Bearer";
			internal const string SCHEME_PREFIX = SCHEME + " ";
		}

		internal const string D2L_AUTH_COOKIE_NAME = "d2lApi";
	}
}
