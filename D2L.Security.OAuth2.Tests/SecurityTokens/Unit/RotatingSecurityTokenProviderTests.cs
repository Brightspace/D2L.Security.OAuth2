using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using D2L.Security.OAuth2.SecurityTokens;
using D2L.Security.OAuth2.SecurityTokens.Default;

using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.SecurityTokens.Unit {
	[TestFixture]
	[Category( "Unit" )]
	internal sealed class RotatingSecurityTokenProviderTests {
		private readonly ISecurityTokenFactory m_securityTokenFactory;
		private ISecurityTokenProvider m_innerSecurityTokenManager;
		private ISecurityTokenProvider m_securityTokenManager;

		public RotatingSecurityTokenProviderTests() {
			m_securityTokenFactory = new RsaSecurityTokenFactory();
		}

		[SetUp]
		public void SetUp() {
			// Each test gets a fresh key store
#pragma warning disable 0618
			m_innerSecurityTokenManager = new InMemorySecurityTokenProvider();
#pragma warning restore 0618

			m_securityTokenManager = new RotatingSecurityTokenProvider(
				m_innerSecurityTokenManager,
				m_securityTokenFactory,
				RotatingSecurityTokenProvider.DEFAULT_ROTATION_BUFFER,
				RotatingSecurityTokenProvider.DEFAULT_TOKEN_LIFETIME
			);
		}

		[TearDown]
		public void TearDown() {
			( m_innerSecurityTokenManager as IDisposable ).Dispose();
		}

		[Test]
		public async void GetLatestToken_NoTokens_CreatesToken() {
			D2LSecurityToken token = await m_securityTokenManager
				.GetLatestTokenAsync()
				.ConfigureAwait( false );

			Assert.NotNull( token );
			Utilities.AssertTokenActive( token );
			Assert.IsTrue( token.HasPrivateKey() );
		}

		[Test]
		public async void GetLatestToken_ExpiredToken_DeletesTokenCreatesAndReturnsNewToken() {
			var oldToken = Utilities.CreateExpiredToken();
			await m_innerSecurityTokenManager
				.SaveAsync( oldToken )
				.ConfigureAwait( false );

			D2LSecurityToken token = await m_securityTokenManager
				.GetLatestTokenAsync()
				.ConfigureAwait( false );

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

			D2LSecurityToken token = await m_securityTokenManager
				.GetLatestTokenAsync()
				.ConfigureAwait( false );

			Assert.NotNull( token );
			Assert.AreNotEqual( oldishToken.KeyId, token.KeyId );
			Utilities.AssertTokenActive( token );
			Assert.IsTrue( token.HasPrivateKey() );
			AssertNumberOfTokensStored( 2 );
		}

		[Test]
		public async void GetLatestToken_ActiveToken_SimplyReturns() {
			var currentToken = Utilities.CreateActiveToken();
			await m_innerSecurityTokenManager
				.SaveAsync( currentToken )
				.ConfigureAwait( false );

			D2LSecurityToken token = await m_securityTokenManager
				.GetLatestTokenAsync()
				.ConfigureAwait( false );

			Assert.NotNull( token );
			Assert.AreEqual( currentToken.KeyId, token.KeyId );
			Utilities.AssertTokenActive( token );
			Assert.IsTrue( token.HasPrivateKey() );
			AssertNumberOfTokensStored( 1 );
		}

		[Test]
		public async void GetAllTokens_DeletesExpiringTokens() {
			var oldToken = Utilities.CreateExpiredToken();
			await m_innerSecurityTokenManager
				.SaveAsync( oldToken )
				.ConfigureAwait( false );

			var tokens = await GetTokens();

			Assert.AreEqual( 0, tokens.Count );
			Utilities.AssertTokensDoNotHavePrivateKeys( tokens );
			AssertNumberOfTokensStored( 0 );
		}

		[Test]
		public async void GetAllTokens_DoesntIgnoreExpiringTokens() {
			var oldishToken = Utilities.CreateExpiringToken();
			await m_innerSecurityTokenManager
				.SaveAsync( oldishToken )
				.ConfigureAwait( false );

			var tokens = await GetTokens();

			Assert.AreEqual( 1, tokens.Count );
			Assert.AreEqual( oldishToken.KeyId, tokens[ 0 ].KeyId );
			AssertNumberOfTokensStored( 1 );
		}

		[Test]
		public async void GetAllTokens_DoesntIgnoreActiveTokens() {
			var activeToken = Utilities.CreateActiveToken();
			await m_innerSecurityTokenManager
				.SaveAsync( activeToken )
				.ConfigureAwait( false );

			var tokens = await GetTokens();

			Assert.AreEqual( 1, tokens.Count );
			Assert.AreEqual( activeToken.KeyId, tokens[ 0 ].KeyId );
			AssertNumberOfTokensStored( 1 );
		}

		private async Task<List<D2LSecurityToken>> GetTokens() {
			IEnumerable<D2LSecurityToken> tokens = await m_securityTokenManager
				.GetAllTokens()
				.ConfigureAwait( false );

			return tokens.ToList();
		}

		private void AssertNumberOfTokensStored( int num ) {
			Utilities.AssertNumberOfTokensStored( m_innerSecurityTokenManager, num );
		}

	}
}
