using System;
using System.Linq;
using System.Threading.Tasks;
using D2L.Security.OAuth2.TestUtilities;
using D2L.Services;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Keys.Development {
	[TestFixture]
	internal sealed class InMemoryPublicKeyDataProviderTests {
		private IPublicKeyDataProvider m_publicKeyDataProvider;

		[SetUp]
		public void SetUp() {
#pragma warning disable 618
			m_publicKeyDataProvider = new InMemoryPublicKeyDataProvider();
#pragma warning restore 618
		}

		[Test]
		public async Task GetById_NoKeys_ReturnsNull() {
			var key = await m_publicKeyDataProvider.GetByIdAsync( Guid.NewGuid() ).SafeAsync();

			Assert.IsNull( key );
		}

		[Test]
		public async Task GetById_IncorrectId_ReturnsKey() {
			var id = Guid.NewGuid();
			var dummyKey = new JsonWebKeyStub( id.ToString() );
			await m_publicKeyDataProvider.SaveAsync( id, dummyKey ).SafeAsync();

			var key = await m_publicKeyDataProvider.GetByIdAsync( Guid.NewGuid() ).SafeAsync();

			Assert.IsNull( key );
		}

		[Test]
		public async Task GetById_CorrectId_ReturnsKey() {
			var expectedId = Guid.NewGuid();
			var expectedKey = new JsonWebKeyStub( expectedId.ToString() );
			await m_publicKeyDataProvider.SaveAsync( expectedId, expectedKey ).SafeAsync();

			var actualKey = await m_publicKeyDataProvider.GetByIdAsync( expectedId ).SafeAsync();

			Assert.AreEqual( expectedKey.Id, actualKey.Id );
			Assert.AreEqual( expectedKey.ExpiresAt, actualKey.ExpiresAt );
		}

		[Test]
		public async Task GetById_CorrectIdWithOthers_ReturnsKey() {
			var expectedId = Guid.NewGuid();
			var expectedKey = new JsonWebKeyStub( expectedId.ToString() );
			await m_publicKeyDataProvider.SaveAsync( expectedId, expectedKey ).SafeAsync();
			var dummyKey = new JsonWebKeyStub( Guid.NewGuid().ToString() );
			await m_publicKeyDataProvider.SaveAsync( new Guid( dummyKey.Id ), dummyKey ).SafeAsync();

			var actualKey = await m_publicKeyDataProvider.GetByIdAsync( expectedId ).SafeAsync();

			Assert.AreEqual( expectedKey.Id, actualKey.Id );
			Assert.AreEqual( expectedKey.ExpiresAt, actualKey.ExpiresAt );
		}

		[Test]
		public async Task GetAll_NoKeys_Empty() {
			var keys = await m_publicKeyDataProvider.GetAllAsync().SafeAsync();

			Assert.IsEmpty( keys );
		}

		[Test]
		public async Task GetAll_ReturnsAllSavedKeys() {
			var expected = new[] {
				new JsonWebKeyStub( Guid.NewGuid().ToString() ),
				new JsonWebKeyStub( Guid.NewGuid().ToString() ),
				new JsonWebKeyStub( Guid.NewGuid().ToString() ),
				new JsonWebKeyStub( Guid.NewGuid().ToString() )
			};

			foreach( var key in expected ) {
				await m_publicKeyDataProvider.SaveAsync( new Guid( key.Id ), key ).SafeAsync();
			}

			var actual = await m_publicKeyDataProvider.GetAllAsync().SafeAsync();

			CollectionAssert.AreEquivalent(
				expected.Select( k => k.Id ),
				actual.Select( k => k.Id ) );
		}

		[Test]
		public async Task SaveAsync_DoubleSave_ThrowsException() {
			var id = Guid.NewGuid();
			var key = new JsonWebKeyStub( id.ToString() );
			await m_publicKeyDataProvider.SaveAsync( id, key ).SafeAsync();

			Assert.Throws<InvalidOperationException>( () => m_publicKeyDataProvider.SaveAsync( id, key ).Wait() );
		}

		[Test]
		public void DeleteAsync_MissingKey_DoesntThrow() {
			Assert.DoesNotThrow( () => m_publicKeyDataProvider.DeleteAsync( Guid.NewGuid() ).Wait() );
		}

		[Test]
		public async Task DeleteAsync_DoesntDeleteOtherKey() {
			var expectedId = Guid.NewGuid();
			var expectedKey = new JsonWebKeyStub( expectedId.ToString() );
			await m_publicKeyDataProvider.SaveAsync( expectedId, expectedKey ).SafeAsync();
			Assert.DoesNotThrow( () => m_publicKeyDataProvider.DeleteAsync( Guid.NewGuid() ).Wait() );
			var actualKey = await m_publicKeyDataProvider.GetByIdAsync( expectedId ).SafeAsync();

			Assert.IsNotNull( actualKey );
			Assert.AreEqual( expectedKey.Id, actualKey.Id );
		}

		[Test]
		public async Task DeleteAsync_DoesSeemToDeleteKey() {
			var expectedId = Guid.NewGuid();
			var expectedKey = new JsonWebKeyStub( expectedId.ToString() );
			Assert.DoesNotThrow( () => m_publicKeyDataProvider.DeleteAsync( expectedId ).Wait() );
			var actualKey = await m_publicKeyDataProvider.GetByIdAsync( expectedId ).SafeAsync();

			Assert.IsNull( actualKey );
		}

		[Test]
		public async Task DeleteAsync_DoubleDelete_DoesSeemToDeleteKey() {
			var expectedId = Guid.NewGuid();
			var expectedKey = new JsonWebKeyStub( expectedId.ToString() );
			Assert.DoesNotThrow( () => m_publicKeyDataProvider.DeleteAsync( expectedId ).Wait() );
			Assert.DoesNotThrow( () => m_publicKeyDataProvider.DeleteAsync( expectedId ).Wait() );
			var actualKey = await m_publicKeyDataProvider.GetByIdAsync( expectedId ).SafeAsync();

			Assert.IsNull( actualKey );
		}
	}
}
