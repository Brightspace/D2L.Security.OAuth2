using System;
using System.IdentityModel.Tokens;
using System.Web;
using D2L.Security.AuthTokenValidation.Default;
using D2L.Security.AuthTokenValidation.JwtValidation;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Unit.Default {

	[TestFixture]
	internal sealed class AuthTokenValidatorTests {

		[Test]
		public void VerifyAndDecode_Expired_Fails() {
			SecurityTokenExpiredException innerException = new SecurityTokenExpiredException();
			IAuthTokenValidator validator = MakeValidatorWhichThrows( innerException );
			IGenericPrincipal principal;

			ValidationResult result = validator.VerifyAndDecode( string.Empty, out principal );
		}

		private IAuthTokenValidator MakeValidatorWhichThrows( Exception innerException ) {
			Mock<IJwtValidator> jwtValidator = new Mock<IJwtValidator>();
			jwtValidator.Setup( x => x.Validate( It.IsAny<string>() ) ).Throws( innerException );
			IAuthTokenValidator validator = new AuthTokenValidator( jwtValidator.Object );
			return validator;
		}

		private HttpRequest CreateHttpRequest() {
			return new HttpRequest( null, "http://www.google.ca", null );
		}
	}
}
