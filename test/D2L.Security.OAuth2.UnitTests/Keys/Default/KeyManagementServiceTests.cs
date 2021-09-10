using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Utilities;
using Moq;
using NUnit.Framework;
using System;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.UnitTests.Keys.Default {
	[TestFixture]
	internal sealed class KeyManagementServiceTests {
		private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

		private static TimeSpan ALittleBit = TimeSpan.FromMinutes( 30 );

		private static readonly OAuth2Configuration KeyConfig = new() {
			// First hour: the key ages (to allow time for caches to flush)
			// Second hour: the key is used exclusively
			// Third hour: we generate a new key but don't use it
			// Forth hour: we switch to the new key
			// Fifth hour: the old key is now expired
			// ....
			KeyLifetime = TimeSpan.FromHours( 4 ),
			KeyTimeUntilUse = TimeSpan.FromHours( 1 ),
			KeyRotationBuffer = TimeSpan.FromHours( 2 )
		};

		private Mock<IPublicKeyDataProvider> m_publicKeys;
		private Mock<IPrivateKeyDataProvider> m_privateKeys;
		private Mock<IDateTimeProvider> m_clock;

		private IKeyManagementService m_kms;
		private IPrivateKeyProvider m_pkp;
		private IDisposable m_disposable;

		[SetUp]
		public void SetUp() {
			m_publicKeys = new( MockBehavior.Strict );
			m_privateKeys = new( MockBehavior.Strict );
			m_clock = new( MockBehavior.Strict );

			SetClock( Now );

			var kms = new KeyManagementService(
				m_publicKeys.Object,
				m_privateKeys.Object,
				m_clock.Object,
				KeyConfig
			);

			m_kms = kms;
			m_pkp = kms;
			m_disposable = kms;
		}

		[TearDown]
		public void TearDown() {
			m_disposable.Dispose();
		}

		[Test]
		public async Task GetSigningCredentialsAsync_OnBoot_NewKey_UsesIt() {
			var key = CreateNewKey();

			UsePrivateKeys( key );

			using var creds = await m_pkp.GetSigningCredentialsAsync();

			AssertCorrectKey( key, creds );
		}

		[Test]
		public async Task GetSigningCredentialsAsync_OnBoot_ActiveKey_UsesIt() {
			var key = CreateActiveKey();

			UsePrivateKeys( key );

			using var creds = await m_pkp.GetSigningCredentialsAsync();

			AssertCorrectKey( key, creds );
		}

		[Test]
		public async Task GetSigningCredentialsAsync_OnBoot_OldKey_UsesIt() {
			var key = CreateOldKey();

			UsePrivateKeys( key );

			using var creds = await m_pkp.GetSigningCredentialsAsync();

			AssertCorrectKey( key, creds );
		}

		[Test]
		public async Task GetSigningCredentialsAsync_OnBoot_ExpiredKey_ReturnsNull() {
			var key = CreateExpiredKey();

			UsePrivateKeys( key );

			using var creds = await m_pkp.GetSigningCredentialsAsync();

			Assert.IsNull( creds );
		}

		[Test]
		public async Task GetSigningCredentialsAsync_HasNewKeyCached_SticksToIt() {
			var firstKey = CreateNewKey();

			await PrimeCacheAsync( firstKey );

			// It would be "better" to use this, but GetSigningCredentialsAsync()
			// won't go looking. RefreshAsync() is used to do that out-of-band.
			var secondKey = CreateActiveKey();

			UsePrivateKeys( firstKey, secondKey );

			using var creds = await m_pkp.GetSigningCredentialsAsync();

			AssertCorrectKey( firstKey, creds );
		}

		[Test]
		public async Task GetSigningCredentialsAsync_TwoActiveKeys_PrefersNewest() {
			var oldActive = CreateActiveKey();
			var newActive = CreateNewActiveKey();

			UsePrivateKeys( oldActive, newActive );

			await m_kms.RefreshKeyAsync();

			using var creds = await m_pkp.GetSigningCredentialsAsync();

			AssertCorrectKey( newActive, creds );
		}

		[Test]
		public async Task RefreshAsync_HasNewKeyCached_ReplacesWithActiveKey() {
			var firstKey = CreateNewKey();

			await PrimeCacheAsync( firstKey );

			var secondKey = CreateActiveKey();

			UsePrivateKeys( firstKey, secondKey );

			var actualDt = await m_kms.RefreshKeyAsync();

			// RefreshAsync chooses an active key and tells the caller they
			// don't need to call back until a minute after a rotation should
			// have happened
			Assert.AreEqual(
				// Time until we generate a new key
				ALittleBit
				// Time until that key is active
				+ KeyConfig.KeyTimeUntilUse
				// Wiggle room
				+ TimeSpan.FromMinutes( 1 ),
				actualDt
			);

			using var creds = await m_pkp.GetSigningCredentialsAsync();

			AssertCorrectKey( secondKey, creds );
		}

		[Test]
		public async Task RefreshAsync_HasVeryNewKeyCached_ReplacesWithLessNewKey() {
			var firstKey = CreateVeryNewKey();

			await PrimeCacheAsync( firstKey );

			var secondKey = CreateNewKey();

			UsePrivateKeys( firstKey, secondKey );

			await m_kms.RefreshKeyAsync();

			using var creds = await m_pkp.GetSigningCredentialsAsync();

			// We prefer the oldest key in this case because it is the least
			// likely to cause cache problems
			AssertCorrectKey( secondKey, creds );
		}

		[Test]
		public async Task RefreshAsync_HasVeryOldKeyCached_NoNewKeys_SaysRetrySoon() {
			var key = CreateVeryOldKey();

			await PrimeCacheAsync( key );

			var actualDt = await m_kms.RefreshKeyAsync();

			Assert.AreEqual( TimeSpan.FromMinutes( 1 ), actualDt );
		}

		[Test]
		public async Task RefreshAsync_NoKeys_SaysRetryVerySoon() {
			UsePrivateKeys();

			var actualDt = await m_kms.RefreshKeyAsync();

			Assert.AreEqual( TimeSpan.FromSeconds( 10 ), actualDt );

			// Double check that we didn't cache anything

			using var creds = await m_pkp.GetSigningCredentialsAsync();

			Assert.IsNull( creds );
		}

		[Test]
		public async Task GenerateNewKeyIfNeededAsync_HasActiveKey_DoesNothing() {
			var key = CreateActiveKey();

			UsePrivateKeys( key );

			await m_kms.GenerateNewKeyIfNeededAsync();

			// If it were to generate a new key it would have to save it which
			// would trigger our strict mocks.
		}

		[Test]
		public async Task GenerateNewKeyIfNeededAsync_HasNewKey_DoesNothing() {
			var key = CreateNewKey();

			UsePrivateKeys( key );

			// Although we'd prefer to use an older key, generating a new one
			// couldn't help: the reason NotBefore exists is to give time for
			// caches to expire, and generating a new key (even with an
			// artificially in-the-past NotBefore) can't change that.

			await m_kms.GenerateNewKeyIfNeededAsync();

			// Again, relying on strict mocks.
		}

		[Test]
		public async Task GenerateNewKeyIfNeededAsync_NoKey_GeneratesOne() {
			UsePrivateKeys();

			ExpectNewKey();

			await m_kms.GenerateNewKeyIfNeededAsync();

			VerifyNewKeyWasSaved();
		}

		[Test]
		public async Task GenerateNewKeyIfNeededAsync_OldKey_GeneratesOne() {
			var key = CreateOldKey();

			UsePrivateKeys( key );

			ExpectNewKey();

			await m_kms.GenerateNewKeyIfNeededAsync();

			VerifyNewKeyWasSaved();
		}

		private void ExpectNewKey() {
			m_publicKeys.Setup( pub => pub.SaveAsync( It.IsAny<Guid>(), It.IsAny<JsonWebKey>() ) )
				.Returns( Task.CompletedTask )
				.Verifiable();

			m_privateKeys.Setup( priv => priv.SaveAsync( It.IsAny<PrivateKeyData>() ) )
				.Returns( Task.CompletedTask )
				.Verifiable();
		}

		private void VerifyNewKeyWasSaved() {
			m_publicKeys.VerifyAll();
			m_privateKeys.VerifyAll();
		}

		private async Task PrimeCacheAsync( PrivateKeyData key ) {
			UsePrivateKeys( key );

			using var creds = await m_pkp.GetSigningCredentialsAsync();

			AssertCorrectKey( key, creds );
		}

		private void AssertCorrectKey( PrivateKeyData expected, D2LSecurityToken actual ) {
			Assert.IsNotNull( actual );
			Assert.AreEqual( expected.Id, actual.Id );
		}

		private void SetClock( DateTimeOffset t )
			=> m_clock.Setup( c => c.UtcNow ).Returns( t );

		private void UsePrivateKeys( params PrivateKeyData[] keys ) {
			m_privateKeys.Setup( pkp => pkp.GetAllAsync( Now ) )
				.ReturnsAsync( keys );
		}

		private PrivateKeyData CreateVeryNewKey() {
			var key = CreateKey( Now );

			Assert.IsFalse( key.IsExpired( Now ) );
			Assert.IsFalse( key.IsPastNotBefore( Now ) );
			Assert.IsFalse( key.WouldPreferToRotate( Now, KeyConfig.KeyRotationBuffer ) );

			return key;
		}

		private PrivateKeyData CreateNewKey() {
			var key = CreateKey( Now - ALittleBit );

			Assert.IsFalse( key.IsExpired( Now ) );
			Assert.IsFalse( key.IsPastNotBefore( Now ) );
			Assert.IsFalse( key.WouldPreferToRotate( Now, KeyConfig.KeyRotationBuffer ) );

			return key;
		}

		private PrivateKeyData CreateNewActiveKey() {
			var key = CreateKey( Now - KeyConfig.KeyTimeUntilUse - TimeSpan.FromSeconds( 1 ) );

			Assert.IsFalse( key.IsExpired( Now ) );
			Assert.IsTrue( key.IsPastNotBefore( Now ) );
			Assert.IsFalse( key.WouldPreferToRotate( Now, KeyConfig.KeyRotationBuffer ) );

			return key;
		}

		private PrivateKeyData CreateActiveKey() {
			var key = CreateKey( Now - KeyConfig.KeyTimeUntilUse - ALittleBit );

			Assert.IsFalse( key.IsExpired( Now ) );
			Assert.IsTrue( key.IsPastNotBefore( Now ) );
			Assert.IsFalse( key.WouldPreferToRotate( Now, KeyConfig.KeyRotationBuffer ) );

			return key;
		}

		private PrivateKeyData CreateOldKey() {
			var key = CreateKey( Now - KeyConfig.KeyRotationBuffer - ALittleBit );

			Assert.IsFalse( key.IsExpired( Now ) );
			Assert.IsTrue( key.IsPastNotBefore( Now ) );
			Assert.IsTrue( key.WouldPreferToRotate( Now, KeyConfig.KeyRotationBuffer ) );

			return key;
		}

		private PrivateKeyData CreateVeryOldKey() {
			var key = CreateKey( Now - KeyConfig.KeyLifetime + ALittleBit );

			Assert.IsFalse( key.IsExpired( Now ) );
			Assert.IsTrue( key.IsPastNotBefore( Now ) );
			Assert.IsTrue( key.WouldPreferToRotate( Now, KeyConfig.KeyRotationBuffer ) );

			return key;
		}

		private PrivateKeyData CreateExpiredKey() {
			var key = CreateKey( Now - KeyConfig.KeyLifetime );

			Assert.IsTrue( key.IsExpired( Now ) );

			return key;
		}

		private PrivateKeyData CreateKey( DateTimeOffset createdAt )
			=> new(
				id: Guid.NewGuid().ToString(),
				kind: PrivateKeyData.KeyKinds.Rsa,
				data: null,
				createdAt: createdAt,
				notBefore: createdAt + KeyConfig.KeyTimeUntilUse,
				expiresAt: createdAt + KeyConfig.KeyLifetime
			);
	}
}
