using System;
using System.Net.Http;
using System.Security.Claims;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.TestFramework;
using D2L.Security.OAuth2.Validation.AccessTokens;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Integration.TestFramework {

	[TestFixture]
	[Category( "Integration" )]
	internal sealed class TestAccessTokenTests {
		private const string DEV_AUTH_URL = "https://auth-dev.proddev.d2l/core";

		[Test]
		public async void TestGetToken_WithTenantID_IsValid() {
			string token = await TestAccessToken.GetToken( DEV_AUTH_URL, Guid.NewGuid().ToString() );

			using( var httpClient = new HttpClient() ) {
				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_URL ) );
				Assert.DoesNotThrow( async () => await validator.ValidateAsync( token ) );
			}
		}

		[Test]
		public async void TestGetToken_WithTenantAndUserIdAndXsrf_IsValid() {
			string token = await TestAccessToken.GetToken( DEV_AUTH_URL, Guid.NewGuid().ToString(), "user", "xsrf" );

			using( var httpClient = new HttpClient() ) {
				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_URL ) );
				Assert.DoesNotThrow( async () => await validator.ValidateAsync( token ) );
			}

		}

		[Test]
		public async void TestGetToken_WithClaimAndScope_IsValid() {
			Claim[] claims = { new Claim( Constants.Claims.TENANT_ID, Guid.NewGuid().ToString() ) };
			Scope[] scopes = { new Scope( "group", "resource", "permission" ) };
			string token = await TestAccessToken.GetToken( DEV_AUTH_URL, claims, scopes );

			using( var httpClient = new HttpClient() ) {
				IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator( httpClient, new Uri( DEV_AUTH_URL ) );
				Assert.DoesNotThrow( async () => await validator.ValidateAsync( token ) );
			}

		}

		[Test]
		public void TestGetToken_WithIssuer_Throws() {
			Claim[] claims = { new Claim( Constants.Claims.ISSUER, "issuer" ) };
			Scope[] scopes = { new Scope( "group", "resource", "permission" ) };

			Assert.Throws<ArgumentException>(async () => await TestAccessToken.GetToken( DEV_AUTH_URL, claims, scopes ));
		}
	}
}
