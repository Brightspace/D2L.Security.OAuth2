using System;
using System.Net.Http;
using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Provisioning.Default;

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
			HttpClient httpClient,
			Uri authEndpoint,
			TimeSpan tokenRefreshGracePeriod,
			IAccessTokenProvider inner = null,
			ICache cache = null
		) {
			if( inner != null && cache == null ) {
				throw new InvalidOperationException( "If you provide an inner you need to also provide its cache" );
			}

			if( inner == null )	{
				IAuthServiceClient authServiceClient = new AuthServiceClient(
					httpClient,
					authEndpoint
				);

				inner = new AccessTokenProvider( tokenSigner, authServiceClient );
			}


			if( cache != null ) {
				return inner;
			}

			return new CachedAccessTokenProvider(
				cache,
				inner,
				authEndpoint,
				tokenRefreshGracePeriod
			);
		}
	}
}
