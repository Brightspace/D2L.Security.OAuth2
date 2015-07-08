using System;
using System.Linq;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Keys.Development {
	[TestFixture]
	[Category( "Unit" )]
	sealed class InMemoryPublicKeyDataProviderTests {
		private IPublicKeyDataProvider m_publicKeyDataProvider;

		[SetUp]
		public void SetUp() {
#pragma warning disable 618
			m_publicKeyDataProvider = new InMemoryPublicKeyDataProvider();
#pragma warning restore 618

		}

		[Test]
		public async Task GetById_NoKeys_ReturnsNull() {
			var key = await m_publicKeyDataProvider.GetByIdAsync( Guid.NewGuid() );

			Assert.IsNull( key );
		}

		[Test]
		public async Task GetById_IncorrectId_ReturnsKey() {
			var dummyKey = new JsonWebKeyStub( Guid.NewGuid() );
			await m_publicKeyDataProvider.SaveAsync( dummyKey );

			var key = await m_publicKeyDataProvider.GetByIdAsync( Guid.NewGuid() );

			Assert.IsNull( key );
		}

		[Test]
		public async Task GetById_CorrectId_ReturnsKey() {
			var expectedKey = new JsonWebKeyStub( Guid.NewGuid() );
			await m_publicKeyDataProvider.SaveAsync( expectedKey );

			var actualKey = await m_publicKeyDataProvider.GetByIdAsync( expectedKey.Id );

			Assert.AreEqual( expectedKey.Id, actualKey.Id );
			Assert.AreEqual( expectedKey.ExpiresAt, actualKey.ExpiresAt );
		}

		[Test]
		public async Task GetById_CorrectIdWithOthers_ReturnsKey() {
			var expectedKey = new JsonWebKeyStub( Guid.NewGuid() );
			await m_publicKeyDataProvider.SaveAsync( expectedKey );
			var dummyKey = new JsonWebKeyStub( Guid.NewGuid() );
			await m_publicKeyDataProvider.SaveAsync( dummyKey );

			var actualKey = await m_publicKeyDataProvider.GetByIdAsync( expectedKey.Id );

			Assert.AreEqual( expectedKey.Id, actualKey.Id );
			Assert.AreEqual( expectedKey.ExpiresAt, actualKey.ExpiresAt );
		}

		[Test]
		public async Task GetAll_NoKeys_Empty() {
			var keys = await m_publicKeyDataProvider.GetAllAsync();

			Assert.IsEmpty( keys );
		}

		[Test]
		public async Task GetAll_ReturnsAllSavedKeys() {
			var expected = new[] {
				new JsonWebKeyStub( Guid.NewGuid() ),
				new JsonWebKeyStub( Guid.NewGuid() ),
				new JsonWebKeyStub( Guid.NewGuid() ),
				new JsonWebKeyStub( Guid.NewGuid() )
			};

			foreach( var key in expected ) {
				await m_publicKeyDataProvider.SaveAsync( key );
			}

			var actual = await m_publicKeyDataProvider.GetAllAsync();

			CollectionAssert.AreEquivalent(
				expected.Select( k => k.Id ),
				actual.Select( k => k.Id ) );
		}

		[Test]
		public async Task SaveAsync_DoubleSave_ThrowsException() {
			var key = new JsonWebKeyStub( Guid.NewGuid() );
			await m_publicKeyDataProvider.SaveAsync( key );

			Assert.Throws<InvalidOperationException>( () => m_publicKeyDataProvider.SaveAsync( key ).Wait() );
		}

		[Test]
		public void DeleteAsync_MissingKey_DoesntThrow() {
			Assert.DoesNotThrow( () => m_publicKeyDataProvider.DeleteAsync( Guid.NewGuid() ).Wait() );
		}

		[Test]
		public async Task DeleteAsync_DoesntDeleteOtherKey() {
			var expectedKey = new JsonWebKeyStub( Guid.NewGuid() );
			await m_publicKeyDataProvider.SaveAsync( expectedKey );
			Assert.DoesNotThrow( () => m_publicKeyDataProvider.DeleteAsync( Guid.NewGuid() ).Wait() );
			var actualKey = await m_publicKeyDataProvider.GetByIdAsync( expectedKey.Id );

			Assert.IsNotNull( actualKey );
			Assert.AreEqual( expectedKey.Id, actualKey.Id );
		}

		[Test]
		public async Task DeleteAsync_DoesSeemToDeleteKey() {
			var expectedKey = new JsonWebKeyStub( Guid.NewGuid() );
			Assert.DoesNotThrow( () => m_publicKeyDataProvider.DeleteAsync( expectedKey.Id ).Wait() );
			var actualKey = await m_publicKeyDataProvider.GetByIdAsync( expectedKey.Id );

			Assert.IsNull( actualKey );
		}

		[Test]
		public async Task DeleteAsync_DoubleDelete_DoesSeemToDeleteKey() {
			var expectedKey = new JsonWebKeyStub( Guid.NewGuid() );
			Assert.DoesNotThrow( () => m_publicKeyDataProvider.DeleteAsync( expectedKey.Id ).Wait() );
			Assert.DoesNotThrow( () => m_publicKeyDataProvider.DeleteAsync( expectedKey.Id ).Wait() );
			var actualKey = await m_publicKeyDataProvider.GetByIdAsync( expectedKey.Id );

			Assert.IsNull( actualKey );
		}

	}
}
