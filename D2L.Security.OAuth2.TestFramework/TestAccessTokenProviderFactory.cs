using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Provisioning.Default;
using D2L.Security.OAuth2.TestFramework.Properties;

namespace D2L.Security.OAuth2.TestFramework {
	public static class TestAccessTokenProviderFactory {

		private static readonly Guid TestGuid = new Guid( Resources.TestGuid );

		/// <summary>
		///  Creates an IAccessTokenProvider with test credentials. Your ClaimSet should have the issuer "ExpandoClient". You can request any Scope.
		/// </summary>
		/// <param name="httpClient">The httpClient that makes the request to the auth server</param>
		/// <param name="tokenProvisioningEndpoint">The auth server</param>
		/// <returns>An IAccessTokenProvider with test credentials</returns>
		public static IAccessTokenProvider Create( HttpClient httpClient, String tokenProvisioningEndpoint ) {
			return Create( httpClient, tokenProvisioningEndpoint, TestGuid, TestRSAParametersProvider.TestRSAParameters );
		}

		/// <summary>
		/// Creates an IAccessTokenProvider with the supplied test credentials.
		/// </summary>
		/// <param name="httpClient">The httpClient that makes the request to the auth server</param>
		/// <param name="tokenProvisioningEndpoint">The auth server</param>
		/// <param name="guid"></param>
		/// <param name="rsaParameters"></param>
		/// <returns>An IAccessTokenProvider with the supplied test credentials</returns>
		public static IAccessTokenProvider Create( HttpClient httpClient, String tokenProvisioningEndpoint, Guid guid, RSAParameters rsaParameters ) {
#pragma warning disable 618
			IPrivateKeyProvider privateKeyProvider = new StaticPrivateKeyProvider( guid, rsaParameters );
#pragma warning restore 618
			ITokenSigner tokenSigner = new TokenSigner( privateKeyProvider );
			IAuthServiceClient authServiceClient = new AuthServiceClient( httpClient, new Uri( tokenProvisioningEndpoint ) );
			INonCachingAccessTokenProvider noCacheTokenProvider = new AccessTokenProvider( tokenSigner, authServiceClient );

			return new CachedAccessTokenProvider( noCacheTokenProvider, Timeout.InfiniteTimeSpan );
		}

	}
}
