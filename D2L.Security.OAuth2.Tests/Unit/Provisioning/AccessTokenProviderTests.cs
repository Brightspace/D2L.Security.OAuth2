using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;

using D2L.Security.OAuth2.Keys.Local;
using D2L.Security.OAuth2.Keys.Local.Data;
using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Provisioning.Default;
using D2L.Security.OAuth2.Scopes;

using Moq;

using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Provisioning {
	
	[TestFixture]
	internal sealed partial class AccessTokenProviderTests {

		private static class TestData {
			public const string ISSUER = "someIssuer";
			public const string TENANT_ID = "someTenant";
			public const string USER = "someUser";
			public const string XSRF_TOKEN = "someXsrfToken";
		}

		[Test]
		public async void ProvisionAccessTokenAsync_AssertionTokenIsSigned() {
			byte[] privateKey;
			byte[] publicKey;
			Guid keyId;
			MakeKeyPair( out privateKey, out publicKey, out keyId );

			string actualAssertion = null;
			Mock<IAuthServiceClient> clientMock = new Mock<IAuthServiceClient>();
			clientMock
				.Setup( x => x.ProvisionAccessTokenAsync( It.IsAny<string>(), It.IsAny<IEnumerable<Scope>>() ) )
				.Callback<string, IEnumerable<Scope>>( ( assertion, _ ) => actualAssertion = assertion )
				.ReturnsAsync( null );

#pragma warning disable 618
			IKeyManager keyManager = KeyManagerFactory.Create( new InMemoryPublicKeyDataProvider() );
#pragma warning restore 618

			IAccessTokenProvider provider = new AccessTokenProvider( TestData.ISSUER, keyManager, clientMock.Object );

			var claims = new List<Claim>{
				new Claim( Constants.Claims.TENANT_ID, TestData.TENANT_ID ),
				new Claim( Constants.Claims.USER_ID, TestData.USER ),
				new Claim( Constants.Claims.XSRF_TOKEN, TestData.XSRF_TOKEN )
			};

			var scopes = new Scope[] { };

			await provider.ProvisionAccessTokenAsync( claims, scopes ).SafeAsync();

			var tokenHandler = new JwtSecurityTokenHandler();
			var unvalidatedToken = (JwtSecurityToken)tokenHandler.ReadToken( actualAssertion );

			var publicKeys = (await keyManager.GetAllAsync().SafeAsync()).ToList();

			string expectedKeyId = publicKeys.First().Id.ToString();
			string actualKeyId = unvalidatedToken.Header.SigningKeyIdentifier[ 0 ].Id;

			Assert.AreEqual( 1, publicKeys.Count );
			Assert.AreEqual( TestData.ISSUER, unvalidatedToken.Issuer );
			Assert.AreEqual( expectedKeyId, actualKeyId );

			AssertClaimEquals( unvalidatedToken, Constants.Claims.TENANT_ID, TestData.TENANT_ID );
			AssertClaimEquals( unvalidatedToken, Constants.Claims.USER_ID, TestData.USER );
			AssertClaimEquals( unvalidatedToken, Constants.Claims.XSRF_TOKEN, TestData.XSRF_TOKEN );
		}

		private void AssertClaimEquals( JwtSecurityToken token, string name, string value ) {
			Claim claim = token.Claims.FirstOrDefault( c => c.Type == name );
			Assert.IsNotNull( claim );
			Assert.AreEqual( value, claim.Value );
		}
	}
}
