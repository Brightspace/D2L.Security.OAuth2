using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Caching;
using D2L.Security.OAuth2.Keys.Default.Data;
using D2L.Security.OAuth2.TestUtilities;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Keys.Default {
	[TestFixture]
	internal sealed class RemotePublicKeyProviderTests {
		private Mock<IJwksProvider> m_jwksProvider;
		private Mock<IInMemoryPublicKeyCache> m_keyCache;
		private IPublicKeyProvider m_publicKeyProvider;

		private string SRC_NAMESPACE;
		private string KEY_ID;
		private const string STRING_KEY_ID = "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg";

		[SetUp]
		public void BeforeEach() {
			m_jwksProvider = new Mock<IJwksProvider>( MockBehavior.Strict );
			m_keyCache = new Mock<IInMemoryPublicKeyCache>( MockBehavior.Strict );
			SRC_NAMESPACE = Guid.NewGuid().ToString();
			KEY_ID = Guid.NewGuid().ToString();

			m_jwksProvider
				.Setup( x => x.Namespace )
				.Returns( SRC_NAMESPACE );

			m_publicKeyProvider = new RemotePublicKeyProvider(
				m_jwksProvider.Object,
				m_keyCache.Object
			);
		}

		private static IEnumerable<TestCaseData> TestKeyIds() {
			yield return new TestCaseData( Guid.NewGuid().ToString() );
			yield return new TestCaseData( STRING_KEY_ID );
		}

		[TestCaseSource("TestKeyIds")]
		public async Task ItShouldReturnFromCacheWhenKeyIsInCache( string keyId ) {
			var cachedKey = new D2LSecurityToken(
				keyId,
				DateTime.UtcNow,
				DateTime.UtcNow + TimeSpan.FromHours( 1 ),
				() => null as Tuple<AsymmetricSecurityKey, IDisposable>
			);

			m_keyCache
				.Setup( x => x.Get( SRC_NAMESPACE, keyId ) )
				.Returns( cachedKey );

			D2LSecurityToken result = await m_publicKeyProvider
				.GetByIdAsync( keyId )
				.ConfigureAwait( false );

			m_keyCache
				.Verify( x => x.Get( SRC_NAMESPACE, keyId ) );

			Assert.AreEqual( cachedKey, result );
		}

		[TestCaseSource("TestKeyIds")]
		public async Task ItShouldRetrieveJwksAndCacheKeysWhenKeyIsNotInCache( string keyId ) {
			var seq = new MockSequence();

			// Check for key in cache before fetching
			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( SRC_NAMESPACE, keyId ) )
				.Returns<D2LSecurityToken>( null );

			var otherKeyId = Guid.NewGuid().ToString();
			var jwks = new JsonWebKeySet(
				JsonSerializer.Serialize(
					new {
						keys = new object[] {
							D2LSecurityTokenUtility
								.CreateActiveToken( keyId )
								.ToJsonWebKey()
								.ToJwkDto(),
							D2LSecurityTokenUtility
								.CreateActiveToken( otherKeyId )
								.ToJsonWebKey()
								.ToJwkDto()
						}
					}
				),
				new Uri( "http://localhost/dummy" )
			);
			m_jwksProvider
				.InSequence( seq )
				.Setup( x => x.RequestJwkAsync( keyId ) )
				.ReturnsAsync( jwks );

			// Check for key in cache before caching
			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( SRC_NAMESPACE, keyId ) )
				.Returns<D2LSecurityToken>( null );
			m_keyCache
				.Setup( x => x.Set( SRC_NAMESPACE, It.Is<D2LSecurityToken>( k => k.KeyId == keyId ) ) );

			// Check for other key in cache, exists so doesn't re-cache it
			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( SRC_NAMESPACE, otherKeyId ) )
				.Returns( D2LSecurityTokenUtility.CreateActiveToken( otherKeyId ) );

			var cachedKey = new D2LSecurityToken(
				keyId,
				DateTime.UtcNow,
				DateTime.UtcNow + TimeSpan.FromHours( 1 ),
				() => null as Tuple<AsymmetricSecurityKey, IDisposable>
			);

			// Pulls the key out of cache afterward
			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( SRC_NAMESPACE, keyId ) )
				.Returns( cachedKey );

			D2LSecurityToken result = await m_publicKeyProvider
				.GetByIdAsync( keyId )
				.ConfigureAwait( false );

			m_keyCache.VerifyAll();

			Assert.AreEqual( cachedKey, result );
		}

		[TestCaseSource("TestKeyIds")]
		public async Task ItShouldRetrieveJwksAndIgnoreInvalidKeysWithoutErroring( string keyId ) {
			var seq = new MockSequence();

			// Check for key in cache before fetching
			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( SRC_NAMESPACE, keyId ) )
				.Returns<D2LSecurityToken>( null );

			var otherKeyId = Guid.NewGuid().ToString();
			var jwks = new JsonWebKeySet(
				JsonSerializer.Serialize(
					new {
						keys = new[] {
							D2LSecurityTokenUtility
								.CreateActiveToken( keyId )
								.ToJsonWebKey()
								.ToJwkDto(),
							D2LSecurityTokenUtility
								.CreateTokenWithTimeRemaining( TimeSpan.FromSeconds( -1 ), otherKeyId )
								.ToJsonWebKey()
								.ToJwkDto()
						}
					}
				),
				new Uri( "http://localhost/dummy" )
			);
			m_jwksProvider
				.InSequence( seq )
				.Setup( x => x.RequestJwkAsync( keyId ) )
				.ReturnsAsync( jwks );

			// Check for key in cache before caching
			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( SRC_NAMESPACE, keyId ) )
				.Returns<D2LSecurityToken>( null );
			m_keyCache
				.Setup( x => x.Set( SRC_NAMESPACE, It.Is<D2LSecurityToken>( k => k.KeyId == keyId ) ) );

			// Check for other key in cache before attempting to cache
			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( SRC_NAMESPACE, otherKeyId ) )
				.Returns<D2LSecurityToken>( null );

			var cachedKey = new D2LSecurityToken(
				keyId,
				DateTime.UtcNow,
				DateTime.UtcNow + TimeSpan.FromHours( 1 ),
				() => null as Tuple<AsymmetricSecurityKey, IDisposable>
			);

			// Pulls the key out of cache afterward
			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( SRC_NAMESPACE, keyId ) )
				.Returns( cachedKey );

			D2LSecurityToken result = await m_publicKeyProvider
				.GetByIdAsync( keyId )
				.ConfigureAwait( false );

			m_keyCache.VerifyAll();
			m_keyCache.Verify( x => x.Set( SRC_NAMESPACE, It.IsAny<D2LSecurityToken>() ), Times.Once );

			Assert.AreEqual( cachedKey, result );
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

			m_jwksProvider
				.Setup( x => x.RequestJwksAsync() )
				.ReturnsAsync( new JsonWebKeySet( JsonSerializer.Serialize( new {
					keys = new[] {
						someKey.ToJsonWebKey().ToJwkDto(),
						expiredKey.ToJsonWebKey().ToJwkDto(),
						alreadyCachedKey.ToJsonWebKey().ToJwkDto(),
						stringIdKey.ToJsonWebKey().ToJwkDto(),
					}
				} ), new Uri( "http://localhost/dummy" ) ) );

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
