using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Provisioning.Default;
using D2L.Security.OAuth2.Scopes;
using D2L.Services;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Provisioning {
	[TestFixture]
	internal sealed class CachedAccessTokenProviderTests {

		private const int TOKEN_EXPIRY_IN_SECONDS = 600;

		private readonly Claim[] m_claims = { new Claim( "abc", "123" ), new Claim( "xyz", "789" ) };
		private readonly Scope[] m_scopes = { new Scope( "a", "b", "c" ), new Scope( "7", "8", "9" ) };

		private Mock<INonCachingAccessTokenProvider> m_accessTokenProviderMock;
		private Mock<ICache> m_userTokenCacheMock;
		private Mock<ICache> m_serviceTokenCacheMock;

		[SetUp]
		public void Setup() {
			m_accessTokenProviderMock = new Mock<INonCachingAccessTokenProvider>( MockBehavior.Strict );
			m_serviceTokenCacheMock = new Mock<ICache>( MockBehavior.Strict );
			m_userTokenCacheMock = new Mock<ICache>( MockBehavior.Strict );
		}

		[TearDown]
		public void Teardown() {
			m_accessTokenProviderMock.VerifyAll();
			m_serviceTokenCacheMock.VerifyAll();
			m_userTokenCacheMock.VerifyAll();
		}

		[Test]
		public async Task ProvisionAccessTokenAsync_NotCached_CallsThroughToAccessTokenProviderAndValueIsThenCached() {

			IAccessToken accessToken = new AccessToken( BuildTestToken() );

			m_accessTokenProviderMock.Setup(
				x => x.ProvisionAccessTokenAsync( It.IsAny<IEnumerable<Claim>>(), It.IsAny<IEnumerable<Scope>>() )
				).Returns( Task.FromResult( accessToken ) );

			m_serviceTokenCacheMock.Setup( x => x.GetAsync( It.IsAny<string>() ) )
				.Returns( Task.FromResult( new CacheResponse( false, null ) ) );
			m_serviceTokenCacheMock.Setup( x => x.SetAsync( It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan>() ) )
				.Returns( Task.CompletedTask );

			IAccessTokenProvider cachedAccessTokenProvider = GetCachedAccessTokenProvider();

			IAccessToken token =
				await cachedAccessTokenProvider.ProvisionAccessTokenAsync( m_claims, m_scopes, m_serviceTokenCacheMock.Object ).SafeAsync();
			Assert.AreEqual( accessToken.Token, token.Token );
		}

		[Test]
		public async Task ProvisionAccessTokenAsync_AlreadyCached_UsesCachedValueAndDoesNotCallThroughToAccessTokenProvider() {

			m_serviceTokenCacheMock.Setup( x => x.GetAsync( It.IsAny<string>() ) )
				.Returns( Task.FromResult( new CacheResponse( true, BuildTestToken() ) ) );

			IAccessTokenProvider cachedAccessTokenProvider = GetCachedAccessTokenProvider();

			IAccessToken token =
				await cachedAccessTokenProvider.ProvisionAccessTokenAsync( m_claims, m_scopes, m_serviceTokenCacheMock.Object ).SafeAsync();
			Assert.NotNull( token );
		}

		[Test]
		public async Task ProvisionAccessTokenAsync_TokenIsAlreadyCachedButIsWithinGracePeriod_NewTokenIsProvisionedAndCached() {

			IAccessToken accessToken = new AccessToken( BuildTestToken() );

			m_serviceTokenCacheMock.Setup( x => x.GetAsync( It.IsAny<string>() ) )
				.Returns( Task.FromResult( new CacheResponse( true, BuildTestToken( tokenExpiryInSeconds: 60 ) ) ) );
			m_serviceTokenCacheMock.Setup( x => x.SetAsync( It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan>() ) )
				.Returns( Task.CompletedTask );

			m_accessTokenProviderMock.Setup( x => x.ProvisionAccessTokenAsync( m_claims, m_scopes ) )
				.Returns( Task.FromResult( accessToken ) );

			const int gracePeriodThatIsBiggerThanTimeToExpiry = TOKEN_EXPIRY_IN_SECONDS + 60;
			IAccessTokenProvider cachedAccessTokenProvider = GetCachedAccessTokenProvider( gracePeriodThatIsBiggerThanTimeToExpiry );

			IAccessToken token =
				await cachedAccessTokenProvider.ProvisionAccessTokenAsync( m_claims, m_scopes, m_serviceTokenCacheMock.Object ).SafeAsync();
			Assert.NotNull( token );
		}

		[Test]
		public async Task ProvisionAccessTokenAsync_UserClaimProvided_UserCacheUsed() {

			m_userTokenCacheMock.Setup( x => x.GetAsync( It.IsAny<string>() ) )
				.Returns( Task.FromResult( new CacheResponse( true, BuildTestToken( specifyUserClaim: true ) ) ) );

			IAccessTokenProvider cachedAccessTokenProvider = GetCachedAccessTokenProvider();

			Claim userClaim = new Claim( Constants.Claims.USER_ID, "user" );
			IAccessToken token =
				await cachedAccessTokenProvider.ProvisionAccessTokenAsync( new[] { userClaim }, m_scopes, m_userTokenCacheMock.Object ).SafeAsync();
			Assert.NotNull( token );
		}

		[Test]
		public async Task ProvisionAccessTokenAsync_ServiceClaimProvided_ServiceCacheUsed() {

			m_serviceTokenCacheMock.Setup( x => x.GetAsync( It.IsAny<string>() ) )
				.Returns( Task.FromResult( new CacheResponse( true, BuildTestToken( specifyUserClaim: false ) ) ) );

			IAccessTokenProvider cachedAccessTokenProvider = GetCachedAccessTokenProvider();

			IAccessToken token =
				await cachedAccessTokenProvider.ProvisionAccessTokenAsync( m_claims, m_scopes, m_serviceTokenCacheMock.Object ).SafeAsync();
			Assert.NotNull( token );
		}

		[Test]
		public async Task ProvisionAccessTokenAsync_CallPassThroughOverload_CallsOtherOverload() {

			const string key = "{\"issuer\":\"https://example.com/\",\"claims\":[{\"name\":\"iss\",\"value\":\"TheIssuer\"}],\"scopes\":[]}";

			m_serviceTokenCacheMock.Setup( x => x.GetAsync( key ) )
				.Returns( Task.FromResult( new CacheResponse( true, BuildTestToken() ) ) );

			ClaimSet claimSet = new ClaimSet( "TheIssuer" );

			IAccessTokenProvider cachedAccessTokenProvider = GetCachedAccessTokenProvider();
			IAccessToken token =
				await cachedAccessTokenProvider.ProvisionAccessTokenAsync( claimSet, Enumerable.Empty<Scope>(), m_serviceTokenCacheMock.Object ).SafeAsync();
			Assert.NotNull( token );
		}

		private IAccessTokenProvider GetCachedAccessTokenProvider( int tokenRefreshGracePeriod = 120 ) {
			return new CachedAccessTokenProvider(
				m_accessTokenProviderMock.Object,
				new Uri( "https://example.com" ),
				TimeSpan.FromSeconds( tokenRefreshGracePeriod )
				);
		}

		private static string BuildTestToken(
			int tokenExpiryInSeconds = TOKEN_EXPIRY_IN_SECONDS,
			bool specifyUserClaim = false
			) {

			string userClaim = specifyUserClaim ? ",\"sub\": \"169\"" : string.Empty;
			long expiry = DateTimeOffset.UtcNow.AddSeconds( tokenExpiryInSeconds ).ToUnixTimeSeconds();

			const string part1 = "{\"alg\": \"RS256\",\"typ\": \"JWT\"}";
			string part2 = string.Format( "{{\"exp\": \"{0}\"{1}}}", expiry, userClaim );
			const string part3 = "thisisnotinspected";

			return Base64UrlEncoder.Encode( part1 ) + "." + Base64UrlEncoder.Encode( part2 ) + "." + Base64UrlEncoder.Encode( part3 );
		}
	}
}
