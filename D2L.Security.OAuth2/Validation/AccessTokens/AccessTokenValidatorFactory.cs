using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Keys.Remote;
using D2L.Security.OAuth2.Keys.Remote.Data;

namespace D2L.Security.OAuth2.Validation.AccessTokens {

	/// <summary>
	/// A factory for creating <see cref="IAccessTokenValidator"/> instances.
	/// </summary>
	public static class AccessTokenValidatorFactory {

		/// <summary>
		/// Creates an <see cref="IAccessTokenValidator"/> instance.
		/// </summary>
		/// <param name="cache">Optionally cache JWKs (keys).</param>
		/// <returns>A cache should be provided to prevent calling out to an external service to get the JWKs on each request.</returns>
		public static IAccessTokenValidator Create( ICache cache = null ) {
			if( cache == null ) {
				cache = new NullCache();
			}

			IJwksProvider jwksProvider = new JwksProvider();
			IJwksProvider cacheJwksProvider = new CachedJwksProvider( cache, jwksProvider );
			
			IPublicKeyProvider tokenProvider = new PublicKeyProvider( cacheJwksProvider );
			IAccessTokenValidator validator = new AccessTokenValidator( tokenProvider );
			
			return validator;
		}
	}
}
