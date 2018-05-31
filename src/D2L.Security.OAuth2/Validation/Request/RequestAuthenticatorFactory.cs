using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Validation.Request {

	/// <summary>
	/// A factory for creating <see cref="IRequestAuthenticator"/> instances.
	/// </summary>
	public static class RequestAuthenticatorFactory {

		/// <summary>
		/// Creates an <see cref="IRequestAuthenticator"/> instance.
		/// </summary>
		public static IRequestAuthenticator Create(
			IAccessTokenValidator accessTokenValidator
		) {
			IRequestAuthenticator authenticator = new RequestAuthenticator( accessTokenValidator );
			return authenticator;
		}

	}
}
