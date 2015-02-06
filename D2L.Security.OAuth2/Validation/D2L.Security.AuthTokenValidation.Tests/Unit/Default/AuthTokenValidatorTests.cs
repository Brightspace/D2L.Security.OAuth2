using System;
using System.IdentityModel.Tokens;
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
			IValidatedToken validatedToken;

			ValidationResult result = validator.VerifyAndDecode( string.Empty, out validatedToken );
			Assert.AreEqual( ValidationResult.TokenExpired, result );
		}

		private IAuthTokenValidator MakeValidatorWhichThrows( Exception innerException ) {
			Mock<IJwtValidator> jwtValidator = new Mock<IJwtValidator>();
			jwtValidator.Setup( x => x.Validate( It.IsAny<string>() ) ).Throws( innerException );
			IAuthTokenValidator validator = new AuthTokenValidator( jwtValidator.Object );
			return validator;
		}
	}
}
