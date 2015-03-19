using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.Security.AuthTokenProvisioning.Client;
using D2L.Security.AuthTokenProvisioning.Default;
using D2L.Security.AuthTokenProvisioning.Tests.Utilities;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenProvisioning.Tests.Unit.Default {
	
	[TestFixture]
	internal sealed partial class AuthTokenProviderTests {

		private static class TestData {
			public const string ISSUER = "someIssuer";
			public const string TENANT_ID = "someTenant";
			public static Uri TENANT_URL = new Uri( "https://someTenant.d2l" );
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
			IAuthTokenProvider provider = new AuthTokenProvider( clientMock.Object );

			using( RSACryptoServiceProvider rsaService = MakeCryptoServiceProvider() ) {
				rsaService.ImportCspBlob( privateKey );

				var key = new RsaSecurityKey( rsaService );

				var claims = new ClaimSet(
					issuer: TestData.ISSUER,
					tenantId: TestData.TENANT_ID,
					tenantUrl: TestData.TENANT_URL,
					user: TestData.USER,
					xsrfToken: TestData.XSRF_TOKEN
				);
				var scopes = new Scope[] { };
				var signingToken = provider.CreateSigningToken( key, keyId );

				await provider.ProvisionAccessTokenAsync( claims, scopes, signingToken );
			}

			JwtSecurityToken signatureCheckedAssertion = CheckSignatureAndGetToken( actualAssertion, publicKey );
			Assert.AreEqual( TestData.ISSUER, signatureCheckedAssertion.Issuer );
			Assert.AreEqual( keyId.ToString(), signatureCheckedAssertion.Header[Constants.AssertionGrant.KEY_ID_NAME] );
			signatureCheckedAssertion.AssertHasClaim( Constants.Claims.TENANT_ID, TestData.TENANT_ID );
			signatureCheckedAssertion.AssertHasClaim( Constants.Claims.TENANT_URL, TestData.TENANT_URL.AbsoluteUri );
			signatureCheckedAssertion.AssertHasClaim( Constants.Claims.USER, TestData.USER );
			signatureCheckedAssertion.AssertHasClaim( Constants.Claims.XSRF_TOKEN, TestData.XSRF_TOKEN );
		}
	}
}
