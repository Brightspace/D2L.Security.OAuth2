using System;
using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Keys.Local;
using D2L.Security.OAuth2.Provisioning.Default;

namespace D2L.Security.OAuth2.Provisioning {

	/// <summary>
	/// A factory for creating access token providers, with an optional caching layer.
	/// </summary>
	public static class AccessTokenProviderFactory {

		/// <summary>
		/// Factory method for creating new <see cref="IAccessTokenProvider"/> instances.
		/// Any provided <see cref="ICache"/> instances do not need to check for token 
		/// expiration or grace period because the <see cref="IAccessTokenProvider"/> 
		/// will handle it internally.
		/// </summary>
		/// <returns>A new <see cref="IAccessTokenProvider"/></returns>
		public static IAccessTokenProvider Create(
			IKeyManager keyManager,
			IAuthServiceClient authServiceClient,
			TimeSpan tokenRefreshGracePeriod,
			ICache userTokenCache = null,
			ICache serviceTokenCache = null,
			bool disposeOfClient = true
			) {

			if( userTokenCache == null ) {
				userTokenCache = new NullCache();
			}

			if( serviceTokenCache == null ) {
				serviceTokenCache = new NullCache();
			}

			IAccessTokenProvider accessTokenProvider =
				new AccessTokenProvider( keyManager, authServiceClient, disposeOfClient );

			return new CachedAccessTokenProvider( accessTokenProvider, userTokenCache, serviceTokenCache, tokenRefreshGracePeriod );
		}
	}
}
