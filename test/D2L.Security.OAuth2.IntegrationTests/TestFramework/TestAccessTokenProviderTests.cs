using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Utilities;
using D2L.Security.OAuth2.Validation.AccessTokens;
using NUnit.Framework;
using IAccessToken = D2L.Security.OAuth2.Provisioning.IAccessToken;

namespace D2L.Security.OAuth2.TestFramework {
	[TestFixture]
	internal sealed class TestAccessTokenProviderTests {
		private const string DEV_AUTH_URL = "https://dev-auth.brightspace.com/core";
		private const string DEV_AUTH_JWKS_URL = "https://dev-auth.brightspace.com/core/.well-known/jwks";
		private const string DEV_AUTH_JWK_URL = "https://dev-auth.brightspace.com/core/jwk/";

		private readonly ClaimSet testClaimSet = new ClaimSet( "ExpandoClient", Guid.NewGuid() );
		private readonly Scope[] testScopes = {
			new Scope( "*", "*", "*" )
		};

		[Test]
		public async Task TestAccessTokenProvider_TokenIsValid() {
			using( var httpClient = new HttpClient() ) {
				IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create( httpClient, DEV_AUTH_URL );
				IAccessToken token = await provider.ProvisionAccessTokenAsync( testClaimSet, testScopes ).ConfigureAwait( false );

				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_JWKS_URL ), new Uri( DEV_AUTH_JWK_URL ) );
				Assert.DoesNotThrowAsync( async () => await validator.ValidateAsync( token.Token ).ConfigureAwait( false ) );
			}
		}

		[Test]
		public async Task TestAccessTokenProvider_SuppliedRSAParameters_TokenIsValid() {
			using( var httpClient = new HttpClient() ) {
				IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create( httpClient, DEV_AUTH_URL, TestStaticKeyProvider.TestKeyId, TestStaticKeyProvider.TestRSAParameters );
				IAccessToken token = await provider.ProvisionAccessTokenAsync( testClaimSet, testScopes ).ConfigureAwait( false );

				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_JWKS_URL ), new Uri( DEV_AUTH_JWK_URL ) );
				Assert.DoesNotThrowAsync( async () => await validator.ValidateAsync( token.Token ).ConfigureAwait( false ) );
			}
		}

		[Test]
		public void TestAccessTokenProvider_InvalidRSAParameters_TokenIsInvalid() {
			var randomRsaParameters = new RSACryptoServiceProvider( OAuth2.Keys.Constants.GENERATED_RSA_KEY_SIZE ) { PersistKeyInCsp = false }.ExportParameters( true );

			using( var httpClient = new HttpClient() ) {
				IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create( httpClient, DEV_AUTH_URL, Guid.NewGuid().ToString(), randomRsaParameters );
				Assert.ThrowsAsync<AuthServiceException>( async () => await provider.ProvisionAccessTokenAsync( testClaimSet, testScopes ).ConfigureAwait( false ) );
			}
		}
	}
}
