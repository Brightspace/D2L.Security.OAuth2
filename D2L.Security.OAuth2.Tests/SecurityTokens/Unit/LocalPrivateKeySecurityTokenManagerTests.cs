using System;

using D2L.Security.OAuth2.SecurityTokens;
using D2L.Security.OAuth2.SecurityTokens.Default;

using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.SecurityTokens.Unit {
	[TestFixture]
	[Category("Unit")]
	internal sealed class LocalPrivateKeySecurityTokenManagerTests {
		private ISecurityTokenManager m_innerSecurityTokenManager;
		private ISecurityTokenManager m_securityTokenManager;

		[SetUp]
		public void SetUp() {
			// Each test gets a fresh key store
			m_innerSecurityTokenManager = new InMemorySecurityTokenManager();

			m_securityTokenManager = new LocalPrivateKeySecurityTokenManager(
				m_innerSecurityTokenManager
			);
		}

		[Test]
		public async void GetLastestToken_NoTokens_ReturnsNull() {
			D2LSecurityToken token = await m_securityTokenManager.GetLatestTokenAsync();

			Assert.IsNull( token );
		}

		[Test]
		public async void GetLatestToken_NoTokenButSomeInInner_ReturnsNull() {
			var activeToken = Utilities.CreateActiveToken();
			await m_innerSecurityTokenManager.SaveAsync( activeToken );

			D2LSecurityToken token = await m_securityTokenManager.GetLatestTokenAsync();

			Assert.IsNull( token );
			AssertNumberOfTokensStored( 1 );
		}

		[Test]
		public async void GetLatestToken_HasActiveToken_ReturnsToken() {
			var activeToken = Utilities.CreateActiveToken();
			await m_securityTokenManager.SaveAsync( activeToken );

			D2LSecurityToken token = await m_securityTokenManager.GetLatestTokenAsync();

			Assert.IsNotNull( token );
			Assert.AreEqual( activeToken.KeyId, token.KeyId );
			Assert.IsTrue( token.HasPrivateKey() );
		}

		[Test]
		public async void GetLatestToken_HasExpiredToken_ReturnsToken() {
			var expiredToken = Utilities.CreateExpiredToken();
			await m_securityTokenManager.SaveAsync( expiredToken );

			D2LSecurityToken token = await m_securityTokenManager.GetLatestTokenAsync();

			Assert.IsNotNull( token );
			Assert.AreEqual( expiredToken.KeyId, token.KeyId );
			Assert.IsTrue( token.HasPrivateKey() );
		}

		[Test]
		public async void SaveAsyncTwiceGetLatestTokenInOrder_ReturnsLatestToken() {
			var expiredToken = Utilities.CreateExpiredToken();
			await m_securityTokenManager.SaveAsync( expiredToken );

			var activeToken = Utilities.CreateActiveToken();
			await m_securityTokenManager.SaveAsync( activeToken );

			D2LSecurityToken token = await m_securityTokenManager.GetLatestTokenAsync();

			Utilities.AssertNumberOfTokensStored( m_innerSecurityTokenManager, 2 );
			Assert.AreEqual( activeToken.KeyId, token.KeyId );
			Utilities.AssertTokenActive( token );
			Assert.IsTrue( token.HasPrivateKey() );
		}

		[Test]
		[ExpectedException(typeof(InvalidOperationException))]
		public async void SaveAsyncTwiceGetLatestTokenBackwards_Throws() {
			var activeToken = Utilities.CreateActiveToken();
			await m_securityTokenManager.SaveAsync( activeToken );

			var expiredToken = Utilities.CreateExpiredToken();
			await m_securityTokenManager.SaveAsync( expiredToken );
		}

		[Test]
		[ExpectedException( typeof( InvalidOperationException ) )]
		public async void SaveAsync_PublicKeyOnly_Throws() {
			var token = Utilities.CreateTokenWithoutPrivateKey();
			await m_securityTokenManager.SaveAsync( token );
		}

		[Test]
		public async void DeleteAsyncGetLatestToken_ReturnsNull() {
			var activeToken = Utilities.CreateActiveToken();
			await m_securityTokenManager.SaveAsync( activeToken );

			await m_securityTokenManager.DeleteAsync( activeToken.KeyId );

			D2LSecurityToken token = await m_securityTokenManager.GetLatestTokenAsync();

			Assert.IsNull( token );
		}

		private void AssertNumberOfTokensStored( int num ) {
			Utilities.AssertNumberOfTokensStored( m_innerSecurityTokenManager, num );
		}

	}
}
