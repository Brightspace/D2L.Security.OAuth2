using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Provisioning.Default;

namespace D2L.Security.OAuth2.TestFramework
{
	public static class TestAccessTokenProviderFactory
    {
		private static readonly Guid TestGuid = new Guid( "FA7C07A8-42C8-4C57-9AF2-CCE10C271033" );

		public static IAccessTokenProvider Create(HttpClient httpClient, String tokenProvisioningEndpoint)
		{
			return Create(httpClient, tokenProvisioningEndpoint, TestGuid, TestRSAParametersProvider.TestRSAParameters);
		}

		public static IAccessTokenProvider Create(HttpClient httpClient, String tokenProvisioningEndpoint, Guid guid, RSAParameters rsaParameters)
		{
			IAuthServiceClient authServiceClient = new AuthServiceClient( httpClient, new Uri( tokenProvisioningEndpoint ) );
#pragma warning disable 618
			IPrivateKeyProvider privateKeyProvider = new StaticPrivateKeyProvider( guid, rsaParameters );
#pragma warning restore 618
			ITokenSigner tokenSigner = new TokenSigner( privateKeyProvider );
			INonCachingAccessTokenProvider noCacheTokenProvider = new AccessTokenProvider( tokenSigner, authServiceClient );

			return new CachedAccessTokenProvider( noCacheTokenProvider, Timeout.InfiniteTimeSpan );
		}
    }
}
