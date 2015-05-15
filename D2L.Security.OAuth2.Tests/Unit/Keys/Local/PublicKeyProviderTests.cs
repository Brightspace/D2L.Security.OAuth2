using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Local;
using D2L.Security.OAuth2.Keys.Local.Data;
using D2L.Security.OAuth2.Keys.Local.Default;
using D2L.Security.OAuth2.Tests.Utilities;

using Moq;

using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Keys.Local {
	[TestFixture]
	[Category( "Unit" )]
	internal sealed class PublicKeyProviderTests {
		private Mock<IPublicKeyDataProvider> m_mockPublicKeyDataProvider;
		private IPublicKeyProvider m_publicKeyProvider;
		private List<JsonWebKey> m_allTheKeys;

		[SetUp]
		public void SetUp() {
			m_mockPublicKeyDataProvider = new Mock<IPublicKeyDataProvider>( MockBehavior.Strict );

			m_allTheKeys = new List<JsonWebKey>();

			m_publicKeyProvider = new PublicKeyProvider(
				m_mockPublicKeyDataProvider.Object,
				JsonWebKeyStub.KEY_LIFETIME );

			m_mockPublicKeyDataProvider
				.Setup( pkdp => pkdp.GetAllAsync() )
				.ReturnsAsync( m_allTheKeys );
		}

		[Test]
		public async Task GetByIdAsync_EmptyDb_ReturnsNull() {
			Guid id = Guid.NewGuid();
			m_mockPublicKeyDataProvider.Setup( kp => kp.GetByIdAsync( id ) ).ReturnsAsync( null );

			JsonWebKey result = await m_publicKeyProvider
				.GetByIdAsync( id )
				.SafeAsync();

			Assert.IsNull( result );
		}

		[Test]
		public async Task GetByIdAsync_InvalidId_ReturnsNull() {
			JsonWebKey key = new JsonWebKeyStub( Guid.NewGuid() );
			AddKeyToDb( key );

			JsonWebKey result = await m_publicKeyProvider
				.GetByIdAsync( Guid.NewGuid() )
				.SafeAsync();

			Assert.IsNull( result );
		}

		[Test]
		public async Task GetByIdAsync_ValidId_ReturnsKey() {
			JsonWebKey key = new JsonWebKeyStub( Guid.NewGuid() );
			AddKeyToDb( key );

			JsonWebKey result = await m_publicKeyProvider
				.GetByIdAsync( key.Id )
				.SafeAsync();

			Assert.IsNotNull( result );
			Assert.AreEqual( key.Id, result.Id );
		}

		[Test]
		public async Task GetByIdAsync_ExpiredKey_DeletesAndReturnsNull() {
			JsonWebKey key = new JsonWebKeyStub( Guid.NewGuid(), DateTime.UtcNow - TimeSpan.FromMinutes( 1 ) );
			AddKeyToDb( key );
			m_mockPublicKeyDataProvider.Setup( kp => kp.DeleteAsync( key.Id ) ).Returns( Task.Delay( 0 ) );

			JsonWebKey result = await m_publicKeyProvider
				.GetByIdAsync( key.Id )
				.SafeAsync();

			m_mockPublicKeyDataProvider.Verify( kp => kp.DeleteAsync( key.Id ), Times.Once() );

			Assert.IsNull( result );
		}

		[Test]
		public async Task GetByIdAsync_OtherKeyExpired_GetsDeletedAsWell() {
			JsonWebKey freshKey = new JsonWebKeyStub( Guid.NewGuid() );
			JsonWebKey expiredKey = new JsonWebKeyStub( Guid.NewGuid(), DateTime.UtcNow - TimeSpan.FromSeconds( 1 ) );
			AddKeyToDb( freshKey );
			AddKeyToDb( expiredKey );
			m_mockPublicKeyDataProvider
				.Setup( pkdb => pkdb.DeleteAsync( expiredKey.Id ) )
				.Returns( Task.Delay( 0 ) );

			JsonWebKey result = await m_publicKeyProvider
				.GetByIdAsync( freshKey.Id )
				.SafeAsync();

			Assert.IsNotNull( result );
			Assert.AreEqual( freshKey.Id, result.Id );

			m_mockPublicKeyDataProvider.Verify( pkdp => pkdp.DeleteAsync( expiredKey.Id ), Times.Once );
		}

		[Test]
		public async Task GetAll_EmptyDb_ReturnsEmptySet() {
			m_mockPublicKeyDataProvider
				.Setup( kp => kp.GetAllAsync() )
				.ReturnsAsync( Enumerable.Empty<JsonWebKey>() );

			IEnumerable<JsonWebKey> result = await m_publicKeyProvider
				.GetAllAsync()
				.SafeAsync();

			Assert.IsEmpty( result );
		}

		[Test]
		public async Task GetAll_MixOfKeys_ReturnsUnexpiredAndDeletesExpired() {
			var goodIds = new[] {Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid()};
			var mehIds = new[] {Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid()};
			var keys = new[] {
				new JsonWebKeyStub( goodIds[ 0 ] ),
				new JsonWebKeyStub( mehIds[ 0 ], DateTime.UtcNow - TimeSpan.FromMilliseconds( 1 ) ),
				new JsonWebKeyStub( mehIds[ 1 ], DateTime.UtcNow - TimeSpan.FromMilliseconds( 1 ) ),
				new JsonWebKeyStub( goodIds[ 1 ] ),
				new JsonWebKeyStub( goodIds[ 2 ] ),
				new JsonWebKeyStub( mehIds[ 2 ], DateTime.UtcNow - TimeSpan.FromMilliseconds( 1 ) )
			};

			m_mockPublicKeyDataProvider
				.Setup( kp => kp.GetAllAsync() )
				.ReturnsAsync( keys );

			foreach( var id in mehIds ) {
				var kid = id; // copy the GUID to appease the compiler
				m_mockPublicKeyDataProvider
					.Setup( kp => kp.DeleteAsync( kid ) )
					.Returns( Task.Delay( 0 ) );
			}

			IEnumerable<JsonWebKey> result = await m_publicKeyProvider
				.GetAllAsync()
				.SafeAsync();

			IEnumerable<Guid> ids = result.Select( k => k.Id );

			foreach( var id in mehIds ) {
				var kid = id; // copy the GUID to appease the compiler
				m_mockPublicKeyDataProvider.Verify( kp => kp.DeleteAsync( kid ), Times.Once() );
			}

			CollectionAssert.AreEquivalent( goodIds, ids );
		}

		private void AddKeyToDb( JsonWebKey key ) {
			m_allTheKeys.Add( key );
			m_mockPublicKeyDataProvider
				.Setup( pkdp => pkdp.GetByIdAsync( key.Id ) )
				.ReturnsAsync( key );
		}
	}
}
