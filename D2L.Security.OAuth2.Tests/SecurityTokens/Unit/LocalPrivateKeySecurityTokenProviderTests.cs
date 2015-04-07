using System;

using D2L.Security.OAuth2.SecurityTokens;
using D2L.Security.OAuth2.SecurityTokens.Default;

using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.SecurityTokens.Unit {
	[TestFixture]
	[Category("Unit")]
	internal sealed class LocalPrivateKeySecurityTokenProviderTests {
		private ISecurityTokenProvider m_innerSecurityTokenManager;
		private ISecurityTokenProvider m_securityTokenManager;

		[SetUp]
		public void SetUp() {
			// Each test gets a fresh key store
#pragma warning disable 0618
			m_innerSecurityTokenManager = new InMemorySecurityTokenProvider();
#pragma warning restore 0618

			m_securityTokenManager = new LocalPrivateKeySecurityTokenProvider(
				m_innerSecurityTokenManager
			);
		}

		[TearDown]
		public void TearDown() {
			( m_innerSecurityTokenManager as IDisposable ).Dispose();
			( m_securityTokenManager as IDisposable ).Dispose();
		}

		[Test]
		public async void GetLastestToken_NoTokens_ReturnsNull() {
			D2LSecurityToken token = await m_securityTokenManager
				.GetLatestTokenAsync()
				.ConfigureAwait( false );

			Assert.IsNull( token );
		}

		[Test]
		public async void GetLatestToken_NoTokenButSomeInInner_ReturnsNull() {
			var activeToken = Utilities.CreateActiveToken();
			await m_innerSecurityTokenManager
				.SaveAsync( activeToken )
				.ConfigureAwait( false );

			D2LSecurityToken token = await m_securityTokenManager
				.GetLatestTokenAsync()
				.ConfigureAwait( false );

			Assert.IsNull( token );
			AssertNumberOfTokensStored( 1 );
		}

		[Test]
		public async void GetLatestToken_HasActiveToken_ReturnsToken() {
			var activeToken = Utilities.CreateActiveToken();
			await m_securityTokenManager
				.SaveAsync( activeToken )
				.ConfigureAwait( false );

			D2LSecurityToken token = await m_securityTokenManager
				.GetLatestTokenAsync()
				.ConfigureAwait( false );

			Assert.IsNotNull( token );
			Assert.AreEqual( activeToken.KeyId, token.KeyId );
			Assert.IsTrue( token.HasPrivateKey() );
		}

		[Test]
		public async void GetLatestToken_HasExpiredToken_ReturnsToken() {
			var expiredToken = Utilities.CreateExpiredToken();
			await m_securityTokenManager
				.SaveAsync( expiredToken )
				.ConfigureAwait( false );

			D2LSecurityToken token = await m_securityTokenManager
				.GetLatestTokenAsync()
				.ConfigureAwait( false );

			Assert.IsNotNull( token );
			Assert.AreEqual( expiredToken.KeyId, token.KeyId );
			Assert.IsTrue( token.HasPrivateKey() );
		}

		[Test]
		public async void SaveAsyncTwiceGetLatestTokenInOrder_ReturnsLatestToken() {
			var expiredToken = Utilities.CreateExpiredToken();
			await m_securityTokenManager
				.SaveAsync( expiredToken )
				.ConfigureAwait( false );

			var activeToken = Utilities.CreateActiveToken();
			await m_securityTokenManager
				.SaveAsync( activeToken )
				.ConfigureAwait( false );

			D2LSecurityToken token = await m_securityTokenManager
				.GetLatestTokenAsync()
				.ConfigureAwait( false );

			Utilities.AssertNumberOfTokensStored( m_innerSecurityTokenManager, 2 );
			Assert.AreEqual( activeToken.KeyId, token.KeyId );
			Utilities.AssertTokenActive( token );
			Assert.IsTrue( token.HasPrivateKey() );
		}

		[Test]
		[ExpectedException(typeof(InvalidOperationException))]
		public async void SaveAsyncTwiceGetLatestTokenBackwards_Throws() {
			var activeToken = Utilities.CreateActiveToken();
			await m_securityTokenManager
				.SaveAsync( activeToken )
				.ConfigureAwait( false );

			var expiredToken = Utilities.CreateExpiredToken();
			await m_securityTokenManager
				.SaveAsync( expiredToken )
				.ConfigureAwait( false );
		}

		[Test]
		[ExpectedException( typeof( InvalidOperationException ) )]
		public async void SaveAsync_PublicKeyOnly_Throws() {
			var token = Utilities.CreateTokenWithoutPrivateKey();
			await m_securityTokenManager
				.SaveAsync( token )
				.ConfigureAwait( false );
		}

		[Test]
		public async void DeleteAsyncGetLatestToken_ReturnsNull() {
			var activeToken = Utilities.CreateActiveToken();
			await m_securityTokenManager
				.SaveAsync( activeToken )
				.ConfigureAwait( false );

			await m_securityTokenManager
				.DeleteAsync( activeToken.KeyId )
				.ConfigureAwait( false );

			D2LSecurityToken token = await m_securityTokenManager
				.GetLatestTokenAsync()
				.ConfigureAwait( false );

			Assert.IsNull( token );
		}

		private void AssertNumberOfTokensStored( int num ) {
			Utilities.AssertNumberOfTokensStored( m_innerSecurityTokenManager, num );
		}

	}
}
