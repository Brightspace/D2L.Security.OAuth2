using System;
using System.Net.Http;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Provisioning.Default;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Provisioning {

	/// <summary>
	/// A factory for creating access token provider.
	/// </summary>
	public static class AccessTokenProviderFactory {

		/// <summary>
		/// Factory method for creating new <see cref="IAccessTokenProvider"/> instances. <paramref name="httpClient"/> will not be diposed.
		/// </summary>
		/// <returns>A new <see cref="IAccessTokenProvider"/></returns>
		public static IAccessTokenProvider Create(
			ITokenSigner tokenSigner,
			D2LHttpClient httpClient,
			Uri authEndpoint,
			TimeSpan tokenRefreshGracePeriod
		) {

			IAuthServiceClient authServiceClient = new AuthServiceClient(
				httpClient,
				authEndpoint
			);

			INonCachingAccessTokenProvider accessTokenProvider =
				new AccessTokenProvider( tokenSigner, authServiceClient );

			return new CachedAccessTokenProvider( accessTokenProvider, authEndpoint, tokenRefreshGracePeriod );
		}
	}
}
