using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Utilities;
using D2L.Services;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Keys.Default {
	[TestFixture]
	internal sealed partial class PrivateKeyProviderTests {
		private const long ROTATION_PERIOD_SECONDS = 10 * 60;
		private const long KEY_LIFETIME_SECONDS = 60 * 60;
		private static readonly TimeSpan KEY_LIFETIME = TimeSpan.FromSeconds( KEY_LIFETIME_SECONDS );
		private static readonly TimeSpan ROTATION_PERIOD = TimeSpan.FromSeconds( ROTATION_PERIOD_SECONDS );

		private Mock<ISanePublicKeyDataProvider> m_mockPublicKeyDataProvider;
		private Mock<IDateTimeProvider> m_mockDateTimeProvider;
		private IPrivateKeyProvider m_privateKeyProvider;

		[SetUp]
		public void SetUp() {
			m_mockPublicKeyDataProvider = new Mock<ISanePublicKeyDataProvider>( MockBehavior.Strict );
			m_mockPublicKeyDataProvider.Setup( pkdp => pkdp.SaveAsync( It.IsAny<Guid>(), It.IsAny<JsonWebKey>() ) ).Returns( Task.CompletedTask );

			m_mockDateTimeProvider = new Mock<IDateTimeProvider>();
			m_mockDateTimeProvider.Setup( dp => dp.UtcNow ).Returns( () => DateTime.UtcNow );

			m_privateKeyProvider = RsaPrivateKeyProvider.Factory.Create(
				m_mockPublicKeyDataProvider.Object,
				KEY_LIFETIME,
				ROTATION_PERIOD,
				m_mockDateTimeProvider.Object
			);
		}

		[Test]
		public async Task GetSigningCredentialsAsync_FirstCall_CreatesAndReturnsKey() {
			D2LSecurityToken key = await m_privateKeyProvider.GetSigningCredentialsAsync().SafeAsync();

			m_mockPublicKeyDataProvider.Verify( pkdp => pkdp.SaveAsync( It.IsAny<Guid>(), It.IsAny<JsonWebKey>() ), Times.Once() );

			Assert.NotNull( key );
		}

		[TestCase( 0 )]
		[TestCase( 1 )]
		[TestCase( ( KEY_LIFETIME_SECONDS - ROTATION_PERIOD_SECONDS ) / 2 )]
		[TestCase( KEY_LIFETIME_SECONDS - ROTATION_PERIOD_SECONDS - 1 )]
		public async Task GetSigningCredentialsAsync_SecondCallShortlyAfter_ReturnsSameKey( long offsetSeconds ) {
			DateTime now = DateTime.UtcNow;

			m_mockDateTimeProvider.Setup( dtp => dtp.UtcNow ).Returns( now );
			D2LSecurityToken key1 = await m_privateKeyProvider.GetSigningCredentialsAsync().SafeAsync();

			m_mockDateTimeProvider.Setup( dtp => dtp.UtcNow ).Returns( now + TimeSpan.FromSeconds( offsetSeconds ) );
			D2LSecurityToken key2 = await m_privateKeyProvider.GetSigningCredentialsAsync().SafeAsync();

			m_mockPublicKeyDataProvider.Verify( pkdp => pkdp.SaveAsync( It.IsAny<Guid>(), It.IsAny<JsonWebKey>() ), Times.Once() );

			Assert.AreEqual( key1.KeyId, key2.KeyId );
		}

		[TestCase( 0 )]
		[TestCase( 1 )]
		[TestCase( ROTATION_PERIOD_SECONDS / 2 )]
		[TestCase( ROTATION_PERIOD_SECONDS - 1 )]
		[TestCase( ROTATION_PERIOD_SECONDS )]
		[TestCase( ROTATION_PERIOD_SECONDS + 1 )]
		public async Task GetSigningCredentialsAsync_KeyDuringOrAfterRotationPeriod_ReturnsNewKey( long offsetSeconds ) {
			DateTime now = DateTime.UtcNow;

			m_mockDateTimeProvider.Setup( dtp => dtp.UtcNow ).Returns( now );
			D2LSecurityToken key1 = await m_privateKeyProvider.GetSigningCredentialsAsync().SafeAsync();

			m_mockDateTimeProvider
				.Setup( dtp => dtp.UtcNow )
				.Returns( now + KEY_LIFETIME - ROTATION_PERIOD + TimeSpan.FromSeconds( offsetSeconds ) );

			D2LSecurityToken key2 = await m_privateKeyProvider.GetSigningCredentialsAsync().SafeAsync();

			m_mockPublicKeyDataProvider.Verify( pkdp => pkdp.SaveAsync( It.IsAny<Guid>(), It.IsAny<JsonWebKey>() ), Times.Exactly( 2 ) );

			Assert.AreNotEqual( key1.KeyId, key2.KeyId );
		}

		[Test]
		public async Task GetSigningCredentialsAsync_RaceyFirstCall_CreatesOnlyOneKey() {
			m_mockPublicKeyDataProvider
				.Setup( pkdp => pkdp.SaveAsync( It.IsAny<Guid>(), It.IsAny<JsonWebKey>() ) )
				.Returns( Task.Delay( 100 ) ); // Introduce a delay so that we definitely have some other tasks waiting for the save to complete.

			var tasks = Enumerable
				.Range( 0, 20 )
				.Select( _ => Task.Run( () => m_privateKeyProvider.GetSigningCredentialsAsync() ) )
				.ToList();

			IEnumerable<D2LSecurityToken> keys = await Task.WhenAll( tasks ).SafeAsync();

			m_mockPublicKeyDataProvider.Verify( pkdp => pkdp.SaveAsync( It.IsAny<Guid>(), It.IsAny<JsonWebKey>() ), Times.Once() );
			var ids = keys.Select( k => k.KeyId ).ToList();
			foreach( string id in ids ) {
				Assert.AreEqual( ids[0], id );
			}
		}
	}
}
