using System;
using System.IdentityModel.Tokens;
using System.Web.Script.Serialization;
using D2L.Security.OAuth2.Keys.Caching;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Keys.Default.Data;
using D2L.Security.OAuth2.Tests.Utilities;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Keys.Default {

	[TestFixture]
	internal sealed class RemotePublicKeyProviderTests {

		private Mock<IJwksProvider> m_jwksProvider;
		private Mock<IInMemoryPublicKeyCache> m_keyCache;
		private IPublicKeyProvider m_publicKeyProvider;

		private Guid KEY_ID;

		[SetUp]
		public void BeforeEach() {
			m_jwksProvider = new Mock<IJwksProvider>( MockBehavior.Strict );
			m_keyCache = new Mock<IInMemoryPublicKeyCache>( MockBehavior.Strict );
			KEY_ID = Guid.NewGuid();

			m_publicKeyProvider = new RemotePublicKeyProvider(
				m_jwksProvider.Object,
				m_keyCache.Object
			);
		}

		[Test]
		async public void ItShouldReturnFromCacheWhenKeyIsInCache() {
			var cachedKey = new D2LSecurityToken(
				KEY_ID,
				DateTime.UtcNow,
				DateTime.UtcNow + TimeSpan.FromHours( 1 ),
				() => null as Tuple<AsymmetricSecurityKey, IDisposable>
			);

			m_keyCache
				.Setup( x => x.Get( KEY_ID ) )
				.Returns( cachedKey );

			D2LSecurityToken result = await m_publicKeyProvider
				.GetByIdAsync( KEY_ID )
				.SafeAsync();

			m_keyCache
				.Verify( x => x.Get( KEY_ID ) );

			Assert.AreEqual( cachedKey, result );
		}

		[Test]
		async public void ItShouldRetrieveJwksAndCacheKeysWhenKeyIsNotInCache() {
			var seq = new MockSequence();

			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( KEY_ID ) )
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
				)
			);
			m_jwksProvider
				.InSequence( seq )
				.Setup( x => x.RequestJwksAsync() )
				.ReturnsAsync( jwks );

			m_keyCache
				.Setup( x => x.Set( It.Is<D2LSecurityToken>( k => k.KeyId == KEY_ID ) ) );
			m_keyCache
				.Setup( x => x.Set( It.Is<D2LSecurityToken>( k => k.KeyId == otherKeyId ) ) );

			var cachedKey = new D2LSecurityToken(
				KEY_ID,
				DateTime.UtcNow,
				DateTime.UtcNow + TimeSpan.FromHours( 1 ),
				() => null as Tuple<AsymmetricSecurityKey, IDisposable>
			);
			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( KEY_ID ) )
				.Returns( cachedKey );

			D2LSecurityToken result = await m_publicKeyProvider
				.GetByIdAsync( KEY_ID )
				.SafeAsync();

			m_keyCache.VerifyAll();

			Assert.AreEqual( cachedKey, result );
		}

		[Test]
		async public void ItShouldRetrieveJwksAndIgnoreInvalidKeysWithoutErroring() {
			var seq = new MockSequence();

			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( KEY_ID ) )
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
								.CreateTokenWithTimeRemaining( TimeSpan.FromSeconds( -1 ), otherKeyId )
								.ToJsonWebKey()
								.ToJwkDto()
						}
					}
				)
			);
			m_jwksProvider
				.InSequence( seq )
				.Setup( x => x.RequestJwksAsync() )
				.ReturnsAsync( jwks );

			m_keyCache
				.Setup( x => x.Set( It.Is<D2LSecurityToken>( k => k.KeyId == KEY_ID ) ) );

			var cachedKey = new D2LSecurityToken(
				KEY_ID,
				DateTime.UtcNow,
				DateTime.UtcNow + TimeSpan.FromHours( 1 ),
				() => null as Tuple<AsymmetricSecurityKey, IDisposable>
			);
			m_keyCache
				.InSequence( seq )
				.Setup( x => x.Get( KEY_ID ) )
				.Returns( cachedKey );

			D2LSecurityToken result = await m_publicKeyProvider
				.GetByIdAsync( KEY_ID )
				.SafeAsync();

			m_keyCache.VerifyAll();
			m_keyCache.Verify( x => x.Set( It.IsAny<D2LSecurityToken>() ), Times.Once );

			Assert.AreEqual( cachedKey, result );
		}
	}
}
