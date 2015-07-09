using System;
using System.Net.Http;
using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;
using NUnit.Framework;
using IAccessToken = D2L.Security.OAuth2.Provisioning.IAccessToken;

namespace D2L.Security.OAuth2.TestFramework {

	[TestFixture]
	internal sealed class TestAccessTokenProviderTests {

		private const string DEV_AUTH_URL = "https://auth-dev.proddev.d2l/core";

		[Test]
		public async void TestTestAccessTokenProvider() {
			using (var httpClient = new HttpClient()) {
				IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create( httpClient, DEV_AUTH_URL );
				IAccessToken token = await provider.ProvisionAccessTokenAsync( new ClaimSet( "ExpandoClient", Guid.NewGuid() ), new[] { new Scope( "*", "*", "*" ) } );

				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_URL ) );
				var result = await validator.ValidateAsync(token.Token);

				Assert.AreEqual(result.Status, ValidationStatus.Success);
			}
		}
	}
}
