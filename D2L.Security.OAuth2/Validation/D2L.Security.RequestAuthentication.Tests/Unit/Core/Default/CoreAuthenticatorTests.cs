using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.AuthTokenValidation;
using D2L.Security.RequestAuthentication.Core;
using D2L.Security.RequestAuthentication.Core.Default;
using Moq;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit.Core.Default {
	
	[TestFixture]
	internal sealed class CoreAuthenticatorTests {

		[TestCase( null, null )]
		[TestCase( null, "" )]
		[TestCase( "", null )]
		[TestCase( "", "" )]
		public void Authenticate_NullOrEmptyCookieAndBearerToken_Anonymous( string cookie, string bearerToken ) {
			ICoreAuthenticator authenticator = new CoreAuthenticator( null, true );
			ID2LPrincipal principal;
			
			AuthenticationResult result = authenticator.Authenticate( cookie, "dummyxsrf", bearerToken, out principal );
			Assert.AreEqual( AuthenticationResult.Anonymous, result );
		}

		[TestCase( "jwt", "jwt" )]
		[TestCase( "incookie", "inbearertoken" )]
		public void Authenticate_JwtInBothCookieAndBearerToken_Conflict( string cookie, string bearerToken ) {
			ICoreAuthenticator authenticator = new CoreAuthenticator( null, true );
			ID2LPrincipal principal;

			AuthenticationResult result = authenticator.Authenticate( cookie, "dummyxsrftoken", bearerToken, out principal );
			Assert.AreEqual( AuthenticationResult.LocationConflict, result );
		}

		[Test]
		public void Authenticate_Jwt_IsExtractedFromCookie() {
			IGenericPrincipal claims = new Mock<IGenericPrincipal>().Object;
			Mock<IAuthTokenValidator> validator = new Mock<IAuthTokenValidator>();
			validator.Setup(
				x => x.VerifyAndDecode( It.IsAny<string>(), out claims )
				).Returns( ValidationResult.Success );
			ICoreAuthenticator authenticator = new CoreAuthenticator( validator.Object, false );
			
			ID2LPrincipal principal;
			string cookie = "jwt_in_cookie";
			AuthenticationResult result = authenticator.Authenticate( cookie, "dummyxsrftoken", null, out principal );
			Assert.AreEqual( AuthenticationResult.Success, result );
			validator.Verify( x => x.VerifyAndDecode( cookie, out claims ), Times.Once );
		}

		[Test]
		public void Authenticate_Jwt_IsExtractedFromBearerToken() {
			IGenericPrincipal claims = new Mock<IGenericPrincipal>().Object;
			Mock<IAuthTokenValidator> validator = new Mock<IAuthTokenValidator>();
			validator.Setup(
				x => x.VerifyAndDecode( It.IsAny<string>(), out claims )
				).Returns( ValidationResult.Success );
			ICoreAuthenticator authenticator = new CoreAuthenticator( validator.Object, false );

			ID2LPrincipal principal;
			string bearerToken = "jwt_in_bearer";
			AuthenticationResult result = authenticator.Authenticate( null, "dummyxsrftoken", bearerToken, out principal );
			Assert.AreEqual( AuthenticationResult.Success, result );
			validator.Verify( x => x.VerifyAndDecode( bearerToken, out claims ), Times.Once );
		}

		[Test]
		public void Authenticate_ExpiredJwt_Expired() {
			Assert.Inconclusive();
		}

		[TestCase( "", "" )]
		[TestCase( null, "" )]
		[TestCase( "", null )]
		[TestCase( null, null )]
		[TestCase( null, "inclaims" )]
		[TestCase( "inheader", null )]
		[TestCase( "", "inclaims" )]
		[TestCase( "inheader", "" )]
		[TestCase( "inheader", "inclaims" )]
		[TestCase( "inheader", "inclAims" )]
		[TestCase( "Z", "z" )]
		public void Authenticate_XsrfMismatch( string xsrfInHeader, string xsrfInClaims ) {
			Mock<IGenericPrincipal> claimsMock = new Mock<IGenericPrincipal>();
			claimsMock.SetupGet( x => x.XsrfToken ).Returns( xsrfInClaims );
			IGenericPrincipal claims = claimsMock.Object;

			Mock<IAuthTokenValidator> validator = new Mock<IAuthTokenValidator>();
			validator.Setup(
				x => x.VerifyAndDecode( It.IsAny<string>(), out claims )
				).Returns( ValidationResult.Success );
			ICoreAuthenticator authenticator = new CoreAuthenticator( validator.Object, true );

			ID2LPrincipal principal;
			AuthenticationResult result = authenticator.Authenticate( "dummycookie", xsrfInHeader, "", out principal );
			Assert.AreEqual( AuthenticationResult.XsrfMismatch, result );
		}

		[Test]
		public void Authenticate_XsrfCheckedAndMatch_Success() {
			Mock<IGenericPrincipal> claimsMock = new Mock<IGenericPrincipal>();
			claimsMock.SetupGet( x => x.XsrfToken ).Returns( "somexsrf" );
			IGenericPrincipal claims = claimsMock.Object;

			Mock<IAuthTokenValidator> validator = new Mock<IAuthTokenValidator>();
			validator.Setup(
				x => x.VerifyAndDecode( It.IsAny<string>(), out claims )
				).Returns( ValidationResult.Success );
			ICoreAuthenticator authenticator = new CoreAuthenticator( validator.Object, true );

			ID2LPrincipal principal;
			AuthenticationResult result = authenticator.Authenticate( "dummycookie", "somexsrf", "", out principal );
			Assert.AreEqual( AuthenticationResult.Success, result );
		}
	}
}
