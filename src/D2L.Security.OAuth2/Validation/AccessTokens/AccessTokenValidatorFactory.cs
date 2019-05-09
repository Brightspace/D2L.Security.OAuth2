using System;
using System.Net.Http;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Caching;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Keys.Default.Data;

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
		/// <param name="authEndpoint">The base URI of the remote service</param>
		/// <returns>A new <see cref="IAccessTokenValidator"/></returns>
		public static IAccessTokenValidator CreateRemoteValidator(
			HttpClient httpClient,
			Uri authEndpoint
		) {
			var jwksProvider = new D2LJwksProvider(
				httpClient,
				authEndpoint
			);
			var publicKeyProvider = new RemotePublicKeyProvider(
				jwksProvider,
				new InMemoryPublicKeyCache()
			);

			var result = new AccessTokenValidator( publicKeyProvider );
			return result;
		}

		/// <summary>
		/// Creates an <see cref="IAccessTokenValidator"/> for Standard OAuth2 instance backed by a remote token signer.
		/// </summary>
		/// <param name="httpClient"><see cref="HttpClient"/> instance with which requests will be made. The lifecycle of the <see cref="HttpClient"/> is not managed. It will not be disposed by the validator.</param>
		/// <param name="authEndpoint">The URI of the remote JWKS file</param>
		/// <returns></returns>
		public static IAccessTokenValidator CreateRemoteStandardValidator(
			HttpClient httpClient,
			Uri authEndpoint
		) {
			var jwksProvider = new StandardJwksProvider(
				httpClient,
				authEndpoint
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
