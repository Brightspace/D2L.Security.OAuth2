﻿using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Local;
using D2L.Security.OAuth2.Keys.Remote;
using D2L.Security.OAuth2.Keys.Remote.Data;
using D2L.Security.OAuth2.Tests.Utilities.Mocks;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Exceptions;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Integration.Validation {
	[TestFixture]
	[Category( "Integration" )]
	internal sealed class AccessTokenValidatorTests {
		private AuthServiceMock m_authService;
		private IAccessTokenValidator m_accessTokenValidator;

		[TestFixtureSetUp]
		public void TestFixtureSetUp() {
			m_authService = new AuthServiceMock();	
			var publicKeyProvider = new PublicKeyProvider( new JwksProvider());
			m_accessTokenValidator = new AccessTokenValidator( publicKeyProvider );

			m_authService.SetupJwks().Wait();
		}


		[Test]
		public async Task ValidateAsync_GoodSignature_Succeeds() {
			const string SUBJECT = "123";
			string token = await m_authService
				.SignTokenBackdoor( new UnsignedToken(
					"fake issuer",
					"fake audience",
					new List<Claim> { new Claim( "sub", SUBJECT ) },
					DateTime.UtcNow - TimeSpan.FromSeconds( 1 ),
					DateTime.UtcNow + TimeSpan.FromHours( 1 ) ) )
				.SafeAsync();

			IValidationResponse response = await m_accessTokenValidator
				.ValidateAsync( m_authService.Host, token )
				.SafeAsync();

			Assert.AreEqual( ValidationStatus.Success, response.Status );

			string subject;
			string fakeclaim;
			response.AccessToken.Claims.TryGetClaim( "sub", out subject );
			response.AccessToken.Claims.TryGetClaim( "fakeclaim", out fakeclaim );

			Assert.AreEqual( SUBJECT, subject );
			Assert.IsNull( fakeclaim );
		}

		[Test]
		public async Task ValidateAsync_BadSignature_Fails() {
			string token = await m_authService
				.SignTokenBackdoor( new UnsignedToken(
					"fake issuer",
					"fake audience",
					new List<Claim>(),
					DateTime.UtcNow - TimeSpan.FromSeconds( 1 ),
					DateTime.UtcNow + TimeSpan.FromHours( 1 ) ) )
				.SafeAsync();

			token += "abcd";

			Assert.Throws<SignatureVerificationFailedException>( () => {
				var response = m_accessTokenValidator
					.ValidateAsync( m_authService.Host, token )
					.GetAwaiter()
					.GetResult();
			} );
		}

		[Test]
		public void ValidateAsync_KeyIdNotInAuthService_Fails() {
			// This JWT has a keyId that doesn't match the one in the auth service
			string jwtWithBadKeyId = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.dUQ2bB3anqRmI-wnC4bulmnwo7wAdrvXo3hn3Dp0tuUl01dy2FhsJESJ9BZ2BeykrLRv2EgdbTW3BCBpBqLbrKQaG_XuGX5MrtXFwHE7i9wWmDsetlJn_cvsZlhPg-voI2iGqT-gpiE9GfWcXjTPUCxAbz6Pqepi0-JDS9uTrCg";

			Assert.Throws<PublicKeyNotFoundException>( () => {
				var response = m_accessTokenValidator
					.ValidateAsync( m_authService.Host, jwtWithBadKeyId )
					.GetAwaiter()
					.GetResult();
			} );
		}
	}
}