namespace D2L.Security.RequestAuthentication {
	internal static class Constants {

		internal static class Headers {
			internal const string COOKIE = "Cookie";
			internal const string XSRF = "X-Csrf-Token";
			internal const string AUTHORIZATION = "Authorization";
		}

		internal static class BearerTokens {
			internal const string SCHEME = "Bearer";
			internal const string SCHEME_PREFIX = SCHEME + " ";
		}
	}
}
