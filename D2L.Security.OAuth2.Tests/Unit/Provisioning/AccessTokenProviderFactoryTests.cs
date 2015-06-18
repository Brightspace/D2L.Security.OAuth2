using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Keys.Local;
using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Scopes;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Provisioning {

	[TestFixture]
	[Category( "Unit" )]
	internal sealed class AccessTokenProviderFactoryTests {

		private const string SERIALIZED_TOKEN = "{\"Token\":\"TheToken\",\"ExpiresIn\":600}";

		private readonly Mock<IKeyManager> m_keyManagerMock = new Mock<IKeyManager>();
		private readonly Mock<IAuthServiceClient> m_authServiceClientMock = new Mock<IAuthServiceClient>();

		[Test]
		public void Create_UserCacheProvided_UserCacheHit() {

			Mock<ICache> userTokenCacheMock = new Mock<ICache>();
			userTokenCacheMock.Setup( x => x.GetAsync( It.IsAny<string>() ) )
				.Returns( Task.FromResult( new CacheResponse( true, SERIALIZED_TOKEN ) ) );

			IAccessTokenProvider accessTokenProvider =
				AccessTokenProviderFactory.Create(
					m_keyManagerMock.Object,
					m_authServiceClientMock.Object,
					TimeSpan.FromMinutes( 2 ),
					userTokenCache: userTokenCacheMock.Object,
					serviceTokenCache: null
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
					m_keyManagerMock.Object,
					m_authServiceClientMock.Object,
					TimeSpan.FromMinutes( 2 ),
					userTokenCache: null,
					serviceTokenCache: serviceTokenCacheMock.Object
					);

			Task<IAccessToken> token =
				accessTokenProvider.ProvisionAccessTokenAsync( new[] { new Claim( Constants.Claims.USER_ID, "169" ) }, Enumerable.Empty<Scope>() );

			Assert.NotNull( token );
		}
	}
}
