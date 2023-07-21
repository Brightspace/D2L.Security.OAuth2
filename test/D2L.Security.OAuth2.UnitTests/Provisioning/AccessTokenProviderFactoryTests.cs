using System;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Provisioning.Default;
using D2L.Security.OAuth2.Scopes;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Provisioning {
	[TestFixture]
	internal sealed class AccessTokenProviderFactoryTests {

		private const string SERIALIZED_TOKEN = "{\"Token\":\"TheToken\",\"ExpiresIn\":600}";

		private readonly Mock<ITokenSigner> m_keyManagerMock = new Mock<ITokenSigner>();
		private readonly Mock<IAuthServiceClient> m_authServiceClientMock = new Mock<IAuthServiceClient>();

		[Test]
		public void Create_UserCacheProvided_UserCacheHit() {

			Mock<ICache> userTokenCacheMock = new Mock<ICache>();
			userTokenCacheMock.Setup( x => x.GetAsync( It.IsAny<string>() ) )
				.Returns( Task.FromResult( new CacheResponse( true, SERIALIZED_TOKEN ) ) );

			IAccessTokenProvider accessTokenProvider =
				AccessTokenProviderFactory.Create(
					tokenSigner: m_keyManagerMock.Object,
					httpClient: new HttpClient(),
					authEndpoint: new Uri( "http://foo.d2l" ),
					tokenRefreshGracePeriod: TimeSpan.FromMinutes( 2 )
				);

			Task<IAccessToken> token =
				accessTokenProvider.ProvisionAccessTokenAsync( new[] { new Claim( Constants.Claims.USER_ID, "169" ) }, Enumerable.Empty<Scope>() );

			Assert.NotNull( token );
		}

		[Test]
		public void Create_ServiceCacheProvided_ServiceCacheHit() {

			Mock<ICache> serviceTokenCacheMock = new Mock<ICache>();
			serviceTokenCacheMock.Setup( x => x.GetAsync( It.IsAny<string>() ) )
				.Returns( Task.FromResult( new CacheResponse( true, SERIALIZED_TOKEN ) ) );

			IAccessTokenProvider accessTokenProvider =
				AccessTokenProviderFactory.Create(
					tokenSigner: m_keyManagerMock.Object,
					httpClient: new HttpClient(),
					authEndpoint: new Uri( "http://foo.d2l" ),
					tokenRefreshGracePeriod: TimeSpan.FromMinutes( 2 )
				);

			Task<IAccessToken> token =
				accessTokenProvider.ProvisionAccessTokenAsync( new[] { new Claim( Constants.Claims.USER_ID, "169" ) }, Enumerable.Empty<Scope>() );

			Assert.NotNull( token );
		}
	}
}
