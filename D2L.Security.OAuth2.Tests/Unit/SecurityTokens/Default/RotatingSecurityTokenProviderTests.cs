using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using D2L.Security.OAuth2.SecurityTokens;
using D2L.Security.OAuth2.SecurityTokens.Default;
using D2L.Security.OAuth2.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.SecurityTokens.Default {
	[TestFixture]
	[Category( "Unit" )]
	internal sealed class RotatingSecurityTokenProviderTests {
		private readonly ISecurityTokenFactory m_securityTokenFactory;
		private ISecurityTokenProvider m_innerSecurityTokenProvider;
		private ISecurityTokenProvider m_securityTokenProvider;

		public RotatingSecurityTokenProviderTests() {
			m_securityTokenFactory = new RsaSecurityTokenFactory();
		}

		[SetUp]
		public void SetUp() {
			// Each test gets a fresh key store
#pragma warning disable 0618
			m_innerSecurityTokenProvider = new InMemorySecurityTokenProvider();
#pragma warning restore 0618

			m_securityTokenProvider = new RotatingSecurityTokenProvider(
				m_innerSecurityTokenProvider,
				m_securityTokenFactory,
				RotatingSecurityTokenProvider.DEFAULT_ROTATION_BUFFER,
				RotatingSecurityTokenProvider.DEFAULT_TOKEN_LIFETIME
			);
		}

		[TearDown]
		public void TearDown() {
			( m_innerSecurityTokenProvider as IDisposable ).Dispose();
		}

		[Test]
		public async void GetLatestToken_NoTokens_CreatesToken() {
			D2LSecurityToken token = await m_securityTokenProvider.GetLatestTokenAsync().SafeAsync();

			Assert.NotNull( token );
			D2LSecurityTokenUtility.AssertTokenActive( token );
			Assert.IsTrue( token.HasPrivateKey() );
		}

		[Test]
		public async void GetLatestToken_ExpiredToken_DeletesTokenCreatesAndReturnsNewToken() {
			var oldToken = D2LSecurityTokenUtility.CreateExpiredToken();
			await m_innerSecurityTokenProvider.SaveAsync( oldToken ).SafeAsync();

			D2LSecurityToken token = await m_securityTokenProvider.GetLatestTokenAsync().SafeAsync();

			Assert.NotNull( token );
			Assert.AreNotEqual( oldToken.Id, token.Id );
			D2LSecurityTokenUtility.AssertTokenActive( token );
			Assert.IsTrue( token.HasPrivateKey() );
			AssertNumberOfTokensStored( 1 );
		}

		[Test]
		public async void GetLatestToken_ExpiringToken_IgnoresAndCreatesNewToken() {
			var oldishToken = D2LSecurityTokenUtility.CreateExpiringToken();
			await m_innerSecurityTokenProvider.SaveAsync( oldishToken );

			D2LSecurityToken token = await m_securityTokenProvider.GetLatestTokenAsync().SafeAsync();

			Assert.NotNull( token );
			Assert.AreNotEqual( oldishToken.Id, token.Id );
			D2LSecurityTokenUtility.AssertTokenActive( token );
			Assert.IsTrue( token.HasPrivateKey() );
			AssertNumberOfTokensStored( 2 );
		}

		[Test]
		public async void GetLatestToken_ActiveToken_SimplyReturns() {
			var currentToken = D2LSecurityTokenUtility.CreateActiveToken();
			await m_innerSecurityTokenProvider.SaveAsync( currentToken ).SafeAsync();

			D2LSecurityToken token = await m_securityTokenProvider.GetLatestTokenAsync().SafeAsync();

			Assert.NotNull( token );
			Assert.AreEqual( currentToken.Id, token.Id );
			D2LSecurityTokenUtility.AssertTokenActive( token );
			Assert.IsTrue( token.HasPrivateKey() );
			AssertNumberOfTokensStored( 1 );
		}

		[Test]
		public async void GetAllTokens_DeletesExpiringTokens() {
			var oldToken = D2LSecurityTokenUtility.CreateExpiredToken();
			await m_innerSecurityTokenProvider.SaveAsync( oldToken ).SafeAsync();

			var tokens = await GetTokens();

			Assert.AreEqual( 0, tokens.Count );
			D2LSecurityTokenUtility.AssertTokensDoNotHavePrivateKeys( tokens );
			AssertNumberOfTokensStored( 0 );
		}

		[Test]
		public async void GetAllTokens_DoesntIgnoreExpiringTokens() {
			var oldishToken = D2LSecurityTokenUtility.CreateExpiringToken();
			await m_innerSecurityTokenProvider.SaveAsync( oldishToken ).SafeAsync();

			var tokens = await GetTokens();

			Assert.AreEqual( 1, tokens.Count );
			Assert.AreEqual( oldishToken.Id, tokens[ 0 ].Id );
			AssertNumberOfTokensStored( 1 );
		}

		[Test]
		public async void GetAllTokens_DoesntIgnoreActiveTokens() {
			var activeToken = D2LSecurityTokenUtility.CreateActiveToken();
			await m_innerSecurityTokenProvider.SaveAsync( activeToken ).SafeAsync();

			var tokens = await GetTokens();

			Assert.AreEqual( 1, tokens.Count );
			Assert.AreEqual( activeToken.Id, tokens[ 0 ].Id );
			AssertNumberOfTokensStored( 1 );
		}

		private async Task<List<D2LSecurityToken>> GetTokens() {
			IEnumerable<D2LSecurityToken> tokens = await m_securityTokenProvider.GetAllTokensAsync().SafeAsync();

			return tokens.ToList();
		}

		private void AssertNumberOfTokensStored( int num ) {
			D2LSecurityTokenUtility.AssertNumberOfTokensStored( m_innerSecurityTokenProvider, num );
		}

	}
}
