using System;
using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Validation.Request {

	/// <summary>
	/// A factory for creating <see cref="IRequestAuthenticator"/> instances.
	/// </summary>
	public static class RequestAuthenticatorFactory {
		
		/// <summary>
		/// Creates an <see cref="IRequestAuthenticator"/> instance.
		/// </summary>
		/// <param name="cache">Optionally cache JWKs (keys).</param>
		/// <returns>A cache should be provided to prevent calling out to an external service to get the JWKs on each request.</returns>
		public static IRequestAuthenticator Create( ICache cache = null ) {
			if( cache == null ) {
				cache = new NullCache();
			}

			IAccessTokenValidator validator = AccessTokenValidatorFactory.Create( cache );
			IRequestAuthenticator authenticator = new RequestAuthenticator( validator );
			return authenticator;
		}

	}
}
