using System;
using System.Net.Http;
using System.Security.Cryptography;
using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.TestFramework;
using D2L.Security.OAuth2.Validation.AccessTokens;
using NUnit.Framework;
using IAccessToken = D2L.Security.OAuth2.Provisioning.IAccessToken;

namespace D2L.Security.OAuth2.Tests.Integration.TestFramework {

	[TestFixture]
	[Category( "Integration" )]
	internal sealed class TestAccessTokenProviderTests {

		private const string DEV_AUTH_URL = "https://auth-dev.proddev.d2l/core";

		private readonly ClaimSet testClaimSet = new ClaimSet( "ExpandoClient", Guid.NewGuid() );
		private readonly Scope[] testScopes = {
			new Scope( "*", "*", "*" )
		};

		[Test]
		public async void TestAccessTokenProvider_TokenIsValid() {
			using( var httpClient = new HttpClient() ) {
				IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create( httpClient, DEV_AUTH_URL );
				IAccessToken token = await provider.ProvisionAccessTokenAsync( testClaimSet, testScopes );

				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_URL ) );
				var result = await validator.ValidateAsync( token.Token );

				Assert.AreEqual( result.Status, ValidationStatus.Success );
			}
		}

		[Test]
		public async void TestAccessTokenProvider_SuppliedRSAParameters_TokenIsValid() {
			using( var httpClient = new HttpClient() ) {
				IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create( httpClient, DEV_AUTH_URL, TestRSAParametersProvider.TestKeyId, TestRSAParametersProvider.TestRSAParameters );
				IAccessToken token = await provider.ProvisionAccessTokenAsync( testClaimSet, testScopes );

				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_URL ) );
				var result = await validator.ValidateAsync( token.Token );

				Assert.AreEqual( result.Status, ValidationStatus.Success );
			}
		}

		[Test]
		public void TestAccessTokenProvider_InvalidRSAParameters_TokenIsInvalid() {
			var randomRsaParameters = new RSACryptoServiceProvider(2048) { PersistKeyInCsp = false }.ExportParameters( true );

			using( var httpClient = new HttpClient() ) {
				IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create( httpClient, DEV_AUTH_URL, Guid.NewGuid(), randomRsaParameters );
				Assert.Throws<HttpRequestException>( async () => await provider.ProvisionAccessTokenAsync( testClaimSet, testScopes ) );
			}
		}

	}
}
