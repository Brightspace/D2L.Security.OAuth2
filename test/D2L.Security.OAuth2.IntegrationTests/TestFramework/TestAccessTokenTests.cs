using System;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Services;
using NUnit.Framework;

namespace D2L.Security.OAuth2.TestFramework {
	[TestFixture]
	internal sealed class TestAccessTokenTests {
		private const string DEV_AUTH_URL = "https://dev-auth.brightspace.com/core";
		private const string DEV_AUTH_JWKS_URL = "https://dev-auth.brightspace.com/core/.well-known/jwks";
		private const string DEV_AUTH_JWK_URL = "https://dev-auth.brightspace.com/core/jwk/";

		[Test]
		public async Task TestGetToken_WithTenantID_IsValid() {
			string token = await TestAccessToken.GetToken( DEV_AUTH_URL, Guid.NewGuid().ToString() ).SafeAsync();

			using( var httpClient = new HttpClient() ) {
				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_URL ), new Uri( DEV_AUTH_JWK_URL ) );
				Assert.DoesNotThrowAsync( async () => await validator.ValidateAsync( token ).SafeAsync() );
			}
		}

		[Test]
		public async Task TestGetToken_WithTenantAndUserIdAndXsrf_IsValid() {
			string token = await TestAccessToken.GetToken( DEV_AUTH_URL, Guid.NewGuid().ToString(), "user", "xsrf" ).SafeAsync();

			using( var httpClient = new HttpClient() ) {
				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_URL ), new Uri( DEV_AUTH_JWK_URL ) );
				Assert.DoesNotThrowAsync( async () => await validator.ValidateAsync( token ).SafeAsync() );
			}

		}

		[Test]
		public async Task TestGetToken_WithClaimAndScope_IsValid() {
			Claim[] claims = { new Claim( Constants.Claims.TENANT_ID, Guid.NewGuid().ToString() ) };
			Scope[] scopes = { new Scope( "group", "resource", "permission" ) };
			string token = await TestAccessToken.GetToken( DEV_AUTH_URL, claims, scopes ).SafeAsync();

			using( var httpClient = new HttpClient() ) {
				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_URL ), new Uri( DEV_AUTH_JWK_URL ) );
				Assert.DoesNotThrowAsync( async () => await validator.ValidateAsync( token ).SafeAsync() );
			}

		}

		[Test]
		public void TestGetToken_WithIssuer_Throws() {
			Claim[] claims = { new Claim( Constants.Claims.ISSUER, "issuer" ) };
			Scope[] scopes = { new Scope( "group", "resource", "permission" ) };

			Assert.ThrowsAsync<ArgumentException>( async () => await TestAccessToken.GetToken( DEV_AUTH_URL, claims, scopes ).SafeAsync() );
		}
	}
}
