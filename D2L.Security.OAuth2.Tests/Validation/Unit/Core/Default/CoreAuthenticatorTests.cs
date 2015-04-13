using System.Security.Claims;
using D2L.Security.OAuth2.Validation.Token;
using D2L.Security.OAuth2.Validation.Request.Core;
using D2L.Security.OAuth2.Validation.Request.Core.Default;
using D2L.Security.OAuth2.Validation.Request.Tests.Utilities;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Request.Tests.Unit.Core.Default {
	
	/*
	[TestFixture]
	internal sealed class CoreAuthenticatorTests {

		private const string XSRF_TOKEN_CLAIM_NAME = "xt";

		[TestCase( null, null )]
		[TestCase( null, "" )]
		[TestCase( "", null )]
		[TestCase( "", "" )]
		public void Authenticate_NullOrEmptyCookieAndBearerToken_Anonymous( string cookie, string bearerToken ) {
			ICoreAuthenticator authenticator = new CoreAuthenticator( null, true );
			ID2LPrincipal principal;
			
			AuthenticationStatus result = authenticator.Authenticate( cookie, "dummyxsrf", bearerToken, out principal );
			Assert.AreEqual( AuthenticationStatus.Anonymous, result );
		}

		[TestCase( "jwt", "jwt" )]
		[TestCase( "incookie", "inbearertoken" )]
		public void Authenticate_JwtInBothCookieAndBearerToken_Conflict( string cookie, string bearerToken ) {
			ICoreAuthenticator authenticator = new CoreAuthenticator( null, true );
			ID2LPrincipal principal;

			AuthenticationStatus result = authenticator.Authenticate( cookie, "dummyxsrftoken", bearerToken, out principal );
			Assert.AreEqual( AuthenticationStatus.LocationConflict, result );
		}

		[Test]
		public void Authenticate_Jwt_IsExtractedFromCookie() {
			IValidatedToken validatedToken = new Mock<IValidatedToken>().Object;
			Mock<IAuthTokenValidator> validator = new Mock<IAuthTokenValidator>();
			validator.Setup(
				x => x.VerifyAndDecode( It.IsAny<string>(), out validatedToken )
				).Returns( ValidationResult.Success );
			ICoreAuthenticator authenticator = new CoreAuthenticator( validator.Object, false );
			
			ID2LPrincipal principal;
			string cookie = "jwt_in_cookie";
			AuthenticationStatus result = authenticator.Authenticate( cookie, "dummyxsrftoken", null, out principal );
			Assert.AreEqual( AuthenticationStatus.Success, result );
			validator.Verify( x => x.VerifyAndDecode( cookie, out validatedToken ), Times.Once );
		}

		[Test]
		public void Authenticate_Jwt_IsExtractedFromBearerToken() {
			IValidatedToken validatedToken = new Mock<IValidatedToken>().Object;
			Mock<IAuthTokenValidator> validator = new Mock<IAuthTokenValidator>();
			validator.Setup(
				x => x.VerifyAndDecode( It.IsAny<string>(), out validatedToken )
				).Returns( ValidationResult.Success );
			ICoreAuthenticator authenticator = new CoreAuthenticator( validator.Object, false );

			ID2LPrincipal principal;
			string bearerToken = "jwt_in_bearer";
			AuthenticationStatus result = authenticator.Authenticate( null, "dummyxsrftoken", bearerToken, out principal );
			Assert.AreEqual( AuthenticationStatus.Success, result );
			validator.Verify( x => x.VerifyAndDecode( bearerToken, out validatedToken ), Times.Once );
		}

		[Test]
		public void Authenticate_ExpiredJwt_Expired() {
			ICoreAuthenticator authenticator = MakeAuthenticator( false, ValidationResult.TokenExpired );

			ID2LPrincipal principal;
			AuthenticationStatus result = authenticator.Authenticate( null, "dummyxsrftoken", "bearerToken", out principal );
			Assert.AreEqual( AuthenticationStatus.Expired, result );
		}

		[TestCase( "", "" )]
		[TestCase( null, "" )]
		[TestCase( null, "inclaims" )]
		[TestCase( "", "inclaims" )]
		[TestCase( "inheader", "" )]
		[TestCase( "inheader", "inclaims" )]
		[TestCase( "inheader", "inclAims" )]
		[TestCase( "Z", "z" )]
		public void Authenticate_BrowserUser_XsrfTokensDoNotMatch_XsrfMismatch( string xsrfInHeader, string xsrfInClaims ) {
			Mock<IValidatedToken> validatedTokenMock = new Mock<IValidatedToken>();
			MockXsrfClaim( validatedTokenMock, xsrfInClaims );
			ICoreAuthenticator authenticator = MakeAuthenticator( true, ValidationResult.Success, validatedTokenMock.Object );

			ID2LPrincipal principal;
			AuthenticationStatus result = authenticator.Authenticate( "dummycookie", xsrfInHeader, "", out principal );
			Assert.AreEqual( AuthenticationStatus.XsrfMismatch, result );
		}

		[Test]
		public void Authenticate_XsrfCheckedAndMatch_Success() {
			Mock<IValidatedToken> validatedTokenMock = new Mock<IValidatedToken>();
			MockXsrfClaim( validatedTokenMock, "somexsrf" );
			ICoreAuthenticator authenticator = MakeAuthenticator( true, ValidationResult.Success, validatedTokenMock.Object );

			ID2LPrincipal principal;
			AuthenticationStatus result = authenticator.Authenticate( "dummycookie", "somexsrf", "", out principal );
			Assert.AreEqual( AuthenticationStatus.Success, result );
		}

		[Test]
		public void Authenticate_XsrfChecked_NotBrowserUser_Success() {
			ICoreAuthenticator authenticator = MakeAuthenticator( true, ValidationResult.Success );

			ID2LPrincipal principal;
			AuthenticationStatus result = authenticator.Authenticate( "", "somexsrf", "somebearertoken", out principal );
			Assert.AreEqual( AuthenticationStatus.Success, result );
		}
		
		ICoreAuthenticator MakeAuthenticator( bool checkXsrf, ValidationResult resultFromJwtValidation, IValidatedToken validatedToken = null ) {
			IValidatedToken defaultValidatedToken = new Mock<IValidatedToken>().Object;
			validatedToken = validatedToken ?? defaultValidatedToken;

			Mock<IAuthTokenValidator> validator = new Mock<IAuthTokenValidator>();
			validator.Setup(
				x => x.VerifyAndDecode( It.IsAny<string>(), out validatedToken )
				).Returns( resultFromJwtValidation );
			ICoreAuthenticator authenticator = new CoreAuthenticator( validator.Object, checkXsrf );

			return authenticator;
		}

		private void MockXsrfClaim( Mock<IValidatedToken> validatedTokenMock, string xsrf ) {
			Claim xsrfClaim = new Claim( XSRF_TOKEN_CLAIM_NAME, xsrf );
			Claim[] claims = new Claim[] { xsrfClaim };
			validatedTokenMock.SetupGet( x => x.Claims ).Returns( claims );
		}
	}*/
}
