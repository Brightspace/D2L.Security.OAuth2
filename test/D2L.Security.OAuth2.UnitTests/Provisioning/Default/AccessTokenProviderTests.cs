using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.Scopes;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Provisioning.Default {
	[TestFixture]
	internal sealed class AccessTokenProviderTests {
		private static class TestData {
			public const string ISSUER = "someIssuer";
			public static Guid TENANT_ID = Guid.NewGuid();
			public const string USER = "someUser";
			public const string XSRF_TOKEN = "someXsrfToken";
		}

		private IPublicKeyDataProvider m_publicKeyDataProvider;
		private ITokenSigner m_tokenSigner;
		private INonCachingAccessTokenProvider m_accessTokenProvider;
		private JwtSecurityToken m_actualAssertion;

		[SetUp]
		public void SetUp() {
			Mock<IAuthServiceClient> clientMock = new Mock<IAuthServiceClient>();
			clientMock
				.Setup( x => x.ProvisionAccessTokenAsync( It.IsAny<string>(), It.IsAny<IEnumerable<Scope>>() ) )
				.Callback<string, IEnumerable<Scope>>( ( assertion, _ ) => {
					var tokenHandler = new JwtSecurityTokenHandler();
					m_actualAssertion = (JwtSecurityToken)tokenHandler.ReadToken( assertion );
				} )
				.ReturnsAsync( null );

#pragma warning disable 618
			m_publicKeyDataProvider = new InMemoryPublicKeyDataProvider();
#pragma warning restore 618

			m_tokenSigner = RsaTokenSignerFactory.Create( m_publicKeyDataProvider );
			m_accessTokenProvider = new AccessTokenProvider( m_tokenSigner, clientMock.Object );
		}

		[Test]
		public async void ProvisionAccessTokenAsync_AssertionTokenIsSigned() {
			var claims = new List<Claim>{
				new Claim( Constants.Claims.ISSUER, TestData.ISSUER ),
				new Claim( Constants.Claims.TENANT_ID, TestData.TENANT_ID.ToString() ),
				new Claim( Constants.Claims.USER_ID, TestData.USER ),
				new Claim( Constants.Claims.XSRF_TOKEN, TestData.XSRF_TOKEN )
			};

			var scopes = new Scope[] { };

			await m_accessTokenProvider
				.ProvisionAccessTokenAsync( claims, scopes )
				.SafeAsync();

			var publicKeys = ( await m_publicKeyDataProvider.GetAllAsync().SafeAsync() ).ToList();

			string expectedKeyId = publicKeys.First().Id.ToString();
			string actualKeyId = m_actualAssertion.Header.SigningKeyIdentifier[ 0 ].Id;

			Assert.AreEqual( 1, publicKeys.Count );
			Assert.AreEqual( expectedKeyId, actualKeyId );

			AssertClaimEquals( m_actualAssertion, Constants.Claims.ISSUER, TestData.ISSUER );
			AssertClaimEquals( m_actualAssertion, Constants.Claims.TENANT_ID, TestData.TENANT_ID.ToString() );
			AssertClaimEquals( m_actualAssertion, Constants.Claims.USER_ID, TestData.USER );
			AssertClaimEquals( m_actualAssertion, Constants.Claims.XSRF_TOKEN, TestData.XSRF_TOKEN );
		}

		[Test]
		public async Task ProvisionAccessTokenAsync_LegacyClaimSetOverload_DoesRightThing() {
			var claimSet = new ClaimSet(
				issuer: TestData.ISSUER,
				tenantId: TestData.TENANT_ID,
				user: TestData.USER,
				xsrfToken: TestData.XSRF_TOKEN );

			await m_accessTokenProvider
				.ProvisionAccessTokenAsync( claimSet, new Scope[] { } )
				.SafeAsync();

			AssertClaimEquals( m_actualAssertion, Constants.Claims.ISSUER, TestData.ISSUER );
			AssertClaimEquals( m_actualAssertion, Constants.Claims.TENANT_ID, TestData.TENANT_ID.ToString() );
			AssertClaimEquals( m_actualAssertion, Constants.Claims.USER_ID, TestData.USER );
			AssertClaimEquals( m_actualAssertion, Constants.Claims.XSRF_TOKEN, TestData.XSRF_TOKEN );
		}

		private void AssertClaimEquals( JwtSecurityToken token, string name, string value ) {
			Claim claim = token.Claims.FirstOrDefault( c => c.Type == name );
			Assert.IsNotNull( claim );
			Assert.AreEqual( value, claim.Value );
		}
	}
}
