using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.Services;
using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;
using NUnit.Framework;
using IAccessToken = D2L.Security.OAuth2.Provisioning.IAccessToken;

namespace D2L.Security.OAuth2.TestFramework {
	[TestFixture]
	internal sealed class TestAccessTokenProviderTests {
		private const string DEV_AUTH_URL = "https://dev-auth.brightspace.com/core";

		private readonly ClaimSet testClaimSet = new ClaimSet( "ExpandoClient", Guid.NewGuid() );
		private readonly Scope[] testScopes = {
			new Scope( "*", "*", "*" )
		};

		[Test]
		public async Task TestAccessTokenProvider_TokenIsValid() {
			using( var httpClient = new HttpClient() ) {
				IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create( httpClient, DEV_AUTH_URL );
				IAccessToken token = await provider.ProvisionAccessTokenAsync( testClaimSet, testScopes ).SafeAsync();

				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_URL ) );
				Assert.DoesNotThrowAsync( async () => await validator.ValidateAsync( token.Token ).SafeAsync() );
			}
		}

		[Test]
		public async Task TestAccessTokenProvider_SuppliedRSAParameters_TokenIsValid() {
			using( var httpClient = new HttpClient() ) {
				IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create( httpClient, DEV_AUTH_URL, TestStaticKeyProvider.TestKeyId, TestStaticKeyProvider.TestRSAParameters );
				IAccessToken token = await provider.ProvisionAccessTokenAsync( testClaimSet, testScopes ).SafeAsync();

				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_URL ) );
				Assert.DoesNotThrowAsync( async () => await validator.ValidateAsync( token.Token ).SafeAsync() );
			}
		}

		[Test]
		public void TestAccessTokenProvider_InvalidRSAParameters_TokenIsInvalid() {
			var randomRsaParameters = new RSACryptoServiceProvider( OAuth2.Keys.Constants.GENERATED_RSA_KEY_SIZE ) { PersistKeyInCsp = false }.ExportParameters( true );

			using( var httpClient = new HttpClient() ) {
				IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create( httpClient, DEV_AUTH_URL, Guid.NewGuid(), randomRsaParameters );
				Assert.ThrowsAsync<AuthServiceException>( async () => await provider.ProvisionAccessTokenAsync( testClaimSet, testScopes ).SafeAsync() );
			}
		}
	}
}
