using System;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Validation.Jwks.Data;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Validation.Jwks.Data {
	
	[TestFixture]
	[Category( "Unit" )]
	public class CachedJwksProviderTests {
		
		private const string JWKS_JSON = "somejson";
		private readonly Uri m_uri;
		private readonly string m_cacheKey;

		public CachedJwksProviderTests() {
			m_uri = new Uri( "http://someplace.somewhere" );
			m_cacheKey = m_uri.ToString();
		}

		[Test]
		public async Task CacheHit() {

			await RunTest(
				skipCache: false,
				cacheHit: true,
				innerProviderRequestCalls: Times.Never(),
				cacheGetCalls: Times.Once(),
				cacheSetCalls: Times.Never()
			).SafeAsync();

		}
		
		[Test]
		public async Task CacheMiss() {

			await RunTest(
				skipCache: false,
				cacheHit: false,
				innerProviderRequestCalls: Times.Once(),
				cacheGetCalls: Times.Once(),
				cacheSetCalls: Times.Once()
			).SafeAsync();

		}

		[Test]
		public async Task SkipCache() {

			await RunTest(
				skipCache: true,
				cacheHit: false,
				innerProviderRequestCalls: Times.Once(),
				cacheGetCalls: Times.Never(),
				cacheSetCalls: Times.Once()
			).SafeAsync();

		}

		
		private async Task RunTest(
			bool skipCache,
			bool cacheHit,
			Times innerProviderRequestCalls,
			Times cacheGetCalls,
			Times cacheSetCalls
		) {

			Mock<IJwksProvider> innerProviderMock = CreateInnerProviderMock();
			Mock<ICache> cacheMock = CreateCacheMock( cacheHit );
			
			IJwksProvider cachedProvider = new CachedJwksProvider( cacheMock.Object, innerProviderMock.Object );
			JwksResponse response = await cachedProvider.RequestJwksAsync( m_uri, skipCache: skipCache );

			innerProviderMock.Verify(
				p => p.RequestJwksAsync( m_uri, It.IsAny<bool>() ),
				times: innerProviderRequestCalls
			);

			cacheMock.Verify(
				c => c.GetAsync( m_cacheKey ),
				times: cacheGetCalls
			);

			cacheMock.Verify(
				c => c.SetAsync(
					m_cacheKey,
					JWKS_JSON,
					TimeSpan.FromSeconds( OAuth2.Validation.Jwks.Constants.KEY_MAXAGE_SECONDS )
				),
				times: cacheSetCalls
			);

			Assert.AreEqual( JWKS_JSON, response.JwksJson );
			Assert.AreEqual( cacheHit, response.FromCache );

		}

		private Mock<ICache> CreateCacheMock( bool cacheHit ) {
			var cacheResponse = new CacheResponse(
				success: cacheHit,
				value: JWKS_JSON
			);

			var mock = new Mock<ICache>();
			mock.Setup( c => c.GetAsync( m_cacheKey ) ).Returns( Task.FromResult( cacheResponse ) );

			return mock;
		}

		private Mock<IJwksProvider> CreateInnerProviderMock() {
			
			var jwksResponse = new JwksResponse(
				fromCache: false,
				jwksJson: JWKS_JSON
			);

			var mock = new Mock<IJwksProvider>();
			mock.Setup(
				j => j.RequestJwksAsync(
					It.IsAny<Uri>(),
					It.IsAny<bool>() )
			).Returns( Task.FromResult( jwksResponse ) );

			return mock;
		}

	}
}
