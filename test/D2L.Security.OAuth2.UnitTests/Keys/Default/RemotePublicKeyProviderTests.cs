using System;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using D2L.Services;
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
		private Guid KEY_ID;

		[SetUp]
		public void BeforeEach() {
			m_jwksProvider = new Mock<IJwksProvider>( MockBehavior.Strict );
			m_keyCache = new Mock<IInMemoryPublicKeyCache>( MockBehavior.Strict );
            SRC_NAMESPACE = Guid.NewGuid().ToString();
			KEY_ID = Guid.NewGuid();

            m_jwksProvider
                .Setup( x => x.Namespace )
                .Returns( SRC_NAMESPACE );

            m_publicKeyProvider = new RemotePublicKeyProvider(
				m_jwksProvider.Object,
				m_keyCache.Object
			);
		}

		[Test]
		public async Task ItShouldReturnFromCacheWhenKeyIsInCache() {
			var cachedKey = new D2LSecurityToken(
				KEY_ID,
				DateTime.UtcNow,
				DateTime.UtcNow + TimeSpan.FromHours( 1 ),
				() => null as Tuple<AsymmetricSecurityKey, IDisposable>
			);

			m_keyCache
				.Setup( x => x.Get( SRC_NAMESPACE, KEY_ID ) )
				.Returns( cachedKey );

			D2LSecurityToken result = await m_publicKeyProvider
				.GetByIdAsync( KEY_ID )
				.SafeAsync();

			m_keyCache
				.Verify( x => x.Get( SRC_NAMESPACE, KEY_ID ) );

			Assert.AreEqual( cachedKey, result );
		}

		[Test]
	    public async Task ItShouldRetrieveJwksAndCacheKeysWhenKeyIsNotInCache() {
			var seq = new MockSequence();

			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( SRC_NAMESPACE, KEY_ID ) )
				.Returns<D2LSecurityToken>( null );

			var otherKeyId = Guid.NewGuid();
			var jwks = new JsonWebKeySet(
				new JavaScriptSerializer().Serialize(
					new {
						keys = new object[] {
							D2LSecurityTokenUtility
								.CreateActiveToken( KEY_ID )
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
				.Setup( x => x.RequestJwkAsync( KEY_ID ) )
				.ReturnsAsync( jwks );

			m_keyCache
				.Setup( x => x.Set( SRC_NAMESPACE, It.Is<D2LSecurityToken>( k => k.KeyId == KEY_ID ) ) );
			m_keyCache
				.Setup( x => x.Set( SRC_NAMESPACE, It.Is<D2LSecurityToken>( k => k.KeyId == otherKeyId ) ) );

			var cachedKey = new D2LSecurityToken(
				KEY_ID,
				DateTime.UtcNow,
				DateTime.UtcNow + TimeSpan.FromHours( 1 ),
				() => null as Tuple<AsymmetricSecurityKey, IDisposable>
			);
			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( SRC_NAMESPACE, KEY_ID ) )
				.Returns( cachedKey );

			D2LSecurityToken result = await m_publicKeyProvider
				.GetByIdAsync( KEY_ID )
				.SafeAsync();

			m_keyCache.VerifyAll();

			Assert.AreEqual( cachedKey, result );
		}

		[Test]
		public async Task ItShouldRetrieveJwksAndIgnoreInvalidKeysWithoutErroring() {
			var seq = new MockSequence();

			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( SRC_NAMESPACE, KEY_ID ) )
				.Returns<D2LSecurityToken>( null );

			var otherKeyId = Guid.NewGuid();
			var jwks = new JsonWebKeySet(
				new JavaScriptSerializer().Serialize(
					new {
						keys = new[] {
							D2LSecurityTokenUtility
								.CreateActiveToken( KEY_ID )
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
				.Setup( x => x.RequestJwkAsync( KEY_ID ) )
				.ReturnsAsync( jwks );

			m_keyCache
				.Setup( x => x.Set( SRC_NAMESPACE, It.Is<D2LSecurityToken>( k => k.KeyId == KEY_ID ) ) );

			var cachedKey = new D2LSecurityToken(
				KEY_ID,
				DateTime.UtcNow,
				DateTime.UtcNow + TimeSpan.FromHours( 1 ),
				() => null as Tuple<AsymmetricSecurityKey, IDisposable>
			);
			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( SRC_NAMESPACE, KEY_ID ) )
				.Returns( cachedKey );

			D2LSecurityToken result = await m_publicKeyProvider
				.GetByIdAsync( KEY_ID )
				.SafeAsync();

			m_keyCache.VerifyAll();
			m_keyCache.Verify( x => x.Set( SRC_NAMESPACE, It.IsAny<D2LSecurityToken>() ), Times.Once );

			Assert.AreEqual( cachedKey, result );
		}
	}
}
