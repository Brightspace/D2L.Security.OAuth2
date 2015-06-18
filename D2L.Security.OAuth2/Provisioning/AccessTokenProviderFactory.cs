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
		/// </summary>
		/// <returns>A new <see cref="IAccessTokenProvider"/></returns>
		public static IAccessTokenProvider Create(
			IKeyManager keyManager,
			IAuthServiceClient authServiceClient,
			TimeSpan tokenRefreshGracePeriod,
			bool disposeOfClient = true
			) {

			IAccessTokenProvider accessTokenProvider =
				new AccessTokenProvider( keyManager, authServiceClient, disposeOfClient );

			return new CachedAccessTokenProvider( accessTokenProvider, tokenRefreshGracePeriod );
		}
	}
}
