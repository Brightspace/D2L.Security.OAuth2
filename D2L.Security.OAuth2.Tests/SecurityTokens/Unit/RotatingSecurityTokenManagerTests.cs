using System;
using System.Linq;

using D2L.Security.OAuth2.SecurityTokens;
using D2L.Security.OAuth2.SecurityTokens.Default;

using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.SecurityTokens.Unit {
	[TestFixture]
	[Category( "Unit" )]
	internal sealed class RotatingSecurityTokenManagerTests {
		private readonly ISecurityTokenFactory m_securityTokenFactory;
		private ISecurityTokenManager m_innerSecurityTokenManager;
		private ISecurityTokenManager m_securityTokenManager;

		public RotatingSecurityTokenManagerTests() {
			m_securityTokenFactory = new RsaSecurityTokenFactory();
		}

		[SetUp]
		public void SetUp() {
			// Each test gets a fresh key store
#pragma warning disable 0618
			m_innerSecurityTokenManager = new InMemorySecurityTokenManager();
#pragma warning restore 0618

			m_securityTokenManager = new RotatingSecurityTokenManager(
				m_innerSecurityTokenManager,
				m_securityTokenFactory,
				RotatingSecurityTokenManager.DEFAULT_ROTATION_BUFFER,
				RotatingSecurityTokenManager.DEFAULT_TOKEN_LIFETIME
			);
		}

		[TearDown]
		public void TearDown() {
			( m_innerSecurityTokenManager as IDisposable ).Dispose();
		}

		[Test]
		public async void GetLatestToken_NoTokens_CreatesToken() {
			D2LSecurityToken token = await m_securityTokenManager.GetLatestTokenAsync();

			Assert.NotNull( token );
			Utilities.AssertTokenActive( token );
			Assert.IsTrue( token.HasPrivateKey() );
		}

		[Test]
		public async void GetLatestToken_ExpiredToken_DeletesTokenCreatesAndReturnsNewToken() {
			var oldToken = Utilities.CreateExpiredToken();
			await m_innerSecurityTokenManager.SaveAsync( oldToken );

			D2LSecurityToken token = await m_securityTokenManager.GetLatestTokenAsync();

			Assert.NotNull( token );
			Assert.AreNotEqual( oldToken.KeyId, token.KeyId );
			Utilities.AssertTokenActive( token );
			Assert.IsTrue( token.HasPrivateKey() );
			AssertNumberOfTokensStored( 1 );
		}

		[Test]
		public async void GetLatestToken_ExpiringToken_IgnoresAndCreatesNewToken() {
			var oldishToken = Utilities.CreateExpiringToken();
			await m_innerSecurityTokenManager.SaveAsync( oldishToken );

			D2LSecurityToken token = await m_securityTokenManager.GetLatestTokenAsync();

			Assert.NotNull( token );
			Assert.AreNotEqual( oldishToken.KeyId, token.KeyId );
			Utilities.AssertTokenActive( token );
			Assert.IsTrue( token.HasPrivateKey() );
			AssertNumberOfTokensStored( 2 );
		}

		[Test]
		public async void GetLatestToken_ActiveToken_SimplyReturns() {
			var currentToken = Utilities.CreateActiveToken();
			await m_innerSecurityTokenManager.SaveAsync( currentToken );

			D2LSecurityToken token = await m_securityTokenManager.GetLatestTokenAsync();

			Assert.NotNull( token );
			Assert.AreEqual( currentToken.KeyId, token.KeyId );
			Utilities.AssertTokenActive( token );
			Assert.IsTrue( token.HasPrivateKey() );
			AssertNumberOfTokensStored( 1 );
		}

		[Test]
		public async void GetAllTokens_DeletesExpiringTokens() {
			var oldToken = Utilities.CreateExpiredToken();
			await m_innerSecurityTokenManager.SaveAsync( oldToken );

			var tokens = m_securityTokenManager
				.GetAllTokens()
				.ToList();

			Assert.AreEqual( 0, tokens.Count );
			Utilities.AssertTokensDoNotHavePrivateKeys( tokens );
			AssertNumberOfTokensStored( 0 );
		}

		[Test]
		public async void GetAllTokens_DoesntIgnoreExpiringTokens() {
			var oldishToken = Utilities.CreateExpiringToken();
			await m_innerSecurityTokenManager.SaveAsync( oldishToken );

			var tokens = m_securityTokenManager
				.GetAllTokens()
				.ToList();

			Assert.AreEqual( 1, tokens.Count );
			Assert.AreEqual( oldishToken.KeyId, tokens[ 0 ].KeyId );
			AssertNumberOfTokensStored( 1 );
		}

		[Test]
		public async void GetAllTokens_DoesntIgnoreActiveTokens() {
			var activeToken = Utilities.CreateActiveToken();
			await m_innerSecurityTokenManager.SaveAsync( activeToken );

			var tokens = m_securityTokenManager
				.GetAllTokens()
				.ToList();

			Assert.AreEqual( 1, tokens.Count );
			Assert.AreEqual( activeToken.KeyId, tokens[ 0 ].KeyId );
			AssertNumberOfTokensStored( 1 );
		}

		private void AssertNumberOfTokensStored( int num ) {
			Utilities.AssertNumberOfTokensStored( m_innerSecurityTokenManager, num );
		}

	}
}
