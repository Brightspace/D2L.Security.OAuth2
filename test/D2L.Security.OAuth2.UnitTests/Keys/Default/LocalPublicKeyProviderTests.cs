using System;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Caching;
using D2L.Security.OAuth2.TestUtilities;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Keys.Default {
	[TestFixture]
	internal sealed class LocalPublicKeyProviderTests {

		private const string SRC_NAMESPACE = "Local DB";

		private Mock<ISanePublicKeyDataProvider> m_publicKeyDataProvider;
		private Mock<IInMemoryPublicKeyCache> m_keyCache;
		private IPublicKeyProvider m_publicKeyProvider;

		[SetUp]
		public void BeforeEach() {
			m_publicKeyDataProvider = new( MockBehavior.Strict );
			m_keyCache = new( MockBehavior.Strict );

			m_publicKeyProvider = new LocalPublicKeyProvider(
				m_publicKeyDataProvider.Object,
				m_keyCache.Object
			);
		}

		[Test]
		public async Task PrefetchAsync_ShouldRetrieveJwksAndCacheAllKeysIgnoringErrors() {
			using D2LSecurityToken someKey = D2LSecurityTokenUtility
				.CreateActiveToken();

			using D2LSecurityToken expiredKey = D2LSecurityTokenUtility
				.CreateTokenWithTimeRemaining( remaining: TimeSpan.FromSeconds( -1 ) );

			using D2LSecurityToken alreadyCachedKey = D2LSecurityTokenUtility
				.CreateActiveToken();

			using D2LSecurityToken stringIdKey = D2LSecurityTokenUtility
				.CreateActiveToken( id: "definitelynotauuid" );

			m_publicKeyDataProvider
				.Setup( x => x.GetAllAsync() )
				.ReturnsAsync( new[] {
					someKey.ToJsonWebKey(),
					expiredKey.ToJsonWebKey(),
					alreadyCachedKey.ToJsonWebKey(),
					stringIdKey.ToJsonWebKey(),
				} );

			// Not in cache, so will cache the fetched key
			m_keyCache
				.Setup( x => x.Get( SRC_NAMESPACE, someKey.Id ) )
				.Returns<D2LSecurityToken>( null );
			m_keyCache
				.Setup( x => x.Set( SRC_NAMESPACE, It.Is<D2LSecurityToken>( k => k.Id == someKey.Id ) ) );

			// Not in cache, but is expired, so won't cache the fetched key
			m_keyCache
				.Setup( x => x.Get( SRC_NAMESPACE, expiredKey.Id ) )
				.Returns<D2LSecurityToken>( null );

			// Already in cache, so won't cache the fetched key
			m_keyCache
				.Setup( x => x.Get( SRC_NAMESPACE, alreadyCachedKey.Id ) )
				.Returns( alreadyCachedKey );

			// Not in cache, so will cache the fetched key
			m_keyCache
				.Setup( x => x.Get( SRC_NAMESPACE, stringIdKey.Id ) )
				.Returns<D2LSecurityToken>( null );
			m_keyCache
				.Setup( x => x.Set( SRC_NAMESPACE, It.Is<D2LSecurityToken>( k => k.Id == stringIdKey.Id ) ) );

			await m_publicKeyProvider.PrefetchAsync();
		}
	}
}
