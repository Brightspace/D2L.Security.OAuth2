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
				Assert.DoesNotThrow( async () => await validator.ValidateAsync( token.Token ) );
			}
		}

		[Test]
		public async void TestAccessTokenProvider_SuppliedRSAParameters_TokenIsValid() {
			using( var httpClient = new HttpClient() ) {
				IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create( httpClient, DEV_AUTH_URL, TestStaticKeyProvider.TestKeyId, TestStaticKeyProvider.TestRSAParameters );
				IAccessToken token = await provider.ProvisionAccessTokenAsync( testClaimSet, testScopes );

				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_URL ) );
				Assert.DoesNotThrow( async () => await validator.ValidateAsync( token.Token ) );
			}
		}

		[Test]
		public void TestAccessTokenProvider_InvalidRSAParameters_TokenIsInvalid() {
			var randomRsaParameters = new RSACryptoServiceProvider( OAuth2.Keys.Constants.GENERATED_RSA_KEY_SIZE ) { PersistKeyInCsp = false }.ExportParameters( true );

			using( var httpClient = new HttpClient() ) {
				IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create( httpClient, DEV_AUTH_URL, Guid.NewGuid(), randomRsaParameters );
				Assert.Throws<HttpRequestException>( async () => await provider.ProvisionAccessTokenAsync( testClaimSet, testScopes ) );
			}
		}

	}
}
