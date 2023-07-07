using System;
using System.Net.Http;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Caching;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Keys.Default.Data;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Validation.AccessTokens {

	/// <summary>
	/// A factory for creating <see cref="IAccessTokenValidator"/> instances.
	/// </summary>
	public static class AccessTokenValidatorFactory {

		/// <summary>
		/// Creates an <see cref="IAccessTokenValidator"/> instance backed by local public keys.
		/// </summary>
		/// <param name="publicKeyDataProvider">The <see cref="IPublicKeyDataProvider"/> for the local service</param>
		/// <returns>A new <see cref="IAccessTokenValidator"/></returns>
		public static IAccessTokenValidator CreateLocalValidator(
			IPublicKeyDataProvider publicKeyDataProvider
		) {
			var publicKeyProvider = new LocalPublicKeyProvider(
				PublicKeyDataProviderFactory.CreateInternal( publicKeyDataProvider ),
				new InMemoryPublicKeyCache()
			);

			var result = new AccessTokenValidator( publicKeyProvider );
			return result;
		}

		/// <summary>
		/// Creates an <see cref="IAccessTokenValidator"/> instance backed by a remote token signer.
		/// </summary>
		/// <param name="httpClient"><see cref="HttpClient"/> instance with which requests will be made. The lifecycle of the <see cref="HttpClient"/> is not managed. It will not be disposed by the validator.</param>
		/// <param name="jwksEndpoint">The full URI of the remote JWKS</param>
		/// <param name="jwkEndpoint">The full URI of the remote JWK path</param>
		/// <returns>A new <see cref="IAccessTokenValidator"/></returns>
		public static IAccessTokenValidator CreateRemoteValidator(
			D2LHttpClient httpClient,
			Uri jwksEndpoint,
			Uri jwkEndpoint = null
		) {
			var jwksProvider = new JwksProvider(
				httpClient,
				jwksEndpoint,
				jwkEndpoint
			);
			var publicKeyProvider = new RemotePublicKeyProvider(
				jwksProvider,
				new InMemoryPublicKeyCache()
			);

			var result = new AccessTokenValidator( publicKeyProvider );
			return result;
		}

	}
}
