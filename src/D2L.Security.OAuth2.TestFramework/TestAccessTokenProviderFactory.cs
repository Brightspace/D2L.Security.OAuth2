using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Provisioning.Default;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.TestFramework {
	public static class TestAccessTokenProviderFactory {

		private static readonly string TestKeyId = TestStaticKeyProvider.TestKeyId;

		/// <summary>
		///  Creates an IAccessTokenProvider with test credentials. Your ClaimSet should have the issuer "ExpandoClient". You can request any Scope.
		/// </summary>
		/// <param name="httpClient">The httpClient that makes the request to the auth server</param>
		/// <param name="tokenProvisioningEndpoint">The auth server</param>
		/// <returns>An IAccessTokenProvider with test credentials</returns>
		public static IAccessTokenProvider Create( D2LHttpClient httpClient, String tokenProvisioningEndpoint ) {
			return Create( httpClient, tokenProvisioningEndpoint, TestKeyId, TestStaticKeyProvider.TestRSAParameters );
		}

		/// <summary>
		/// Creates an IAccessTokenProvider with the supplied test credentials.
		/// </summary>
		/// <param name="httpClient">The httpClient that makes the request to the auth server</param>
		/// <param name="tokenProvisioningEndpoint">The auth server</param>
		/// <param name="keyId">The id of the security token</param>
		/// <param name="rsaParameters">The public and private key for the supplied key id</param>
		/// <returns>An IAccessTokenProvider with the supplied test credentials</returns>
		public static IAccessTokenProvider Create( D2LHttpClient httpClient, String tokenProvisioningEndpoint, string keyId, RSAParameters rsaParameters ) {
#pragma warning disable 618
			IPrivateKeyProvider privateKeyProvider = new StaticPrivateKeyProvider( keyId, rsaParameters );
#pragma warning restore 618
			Uri authEndpoint = new Uri( tokenProvisioningEndpoint );
			ITokenSigner tokenSigner = new TokenSigner( privateKeyProvider );
			IAuthServiceClient authServiceClient = new AuthServiceClient( httpClient, authEndpoint );
			INonCachingAccessTokenProvider noCacheTokenProvider = new AccessTokenProvider( tokenSigner, authServiceClient );

			return new CachedAccessTokenProvider( noCacheTokenProvider, authEndpoint, Timeout.InfiniteTimeSpan );
		}

	}
}
