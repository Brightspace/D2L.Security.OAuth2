namespace D2L.Security.OAuth2.Validation.Request {
	internal static class RequestValidationConstants {
		internal static class Headers {
			internal const string AUTHORIZATION = "Authorization";
		}

		internal static class BearerTokens {
			internal const string SCHEME = "Bearer";
			internal const string SCHEME_PREFIX = SCHEME + " ";
		}
	}
}