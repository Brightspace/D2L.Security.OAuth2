using System;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using D2L.Security.OAuth2.Validation.Token.JwtValidation;
using D2L.Security.OAuth2.Validation.Token.JwtValidation.Default;
using D2L.Security.OAuth2.Validation.Token.JwtValidation.Exceptions;
using D2L.Security.OAuth2.Validation.Token.PublicKeys;
using D2L.Security.OAuth2.Validation.Token.Tests.Utilities;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Token.Tests.Unit.JwtValidation.Default {
	
	[TestFixture]
	internal sealed class JwtValidatorTests {

		[Test]
		public void Validate_Success() {
			string jwt = TestTokenProvider.MakeJwt(
				Constants.ALLOWED_SIGNATURE_ALGORITHM,
				Constants.ALLOWED_TOKEN_TYPE,
				"{}",
				TestTokenProvider.CreateRSAParams()
				);
			IJwtValidator validator = MakeValidator( jwt );
			Assert.DoesNotThrow( () => validator.Validate( jwt ) );
		}

		[Test]
		public void Validate_InvalidAlgorithm_Failure() {
			string jwt = TestTokenProvider.MakeJwt(
				"INVALIDALGORITHM",
				Constants.ALLOWED_TOKEN_TYPE,
				"{}",
				TestTokenProvider.CreateRSAParams()
				);
			IJwtValidator validator = MakeValidator( jwt );
			Assert.Throws<InvalidTokenTypeException>( () => validator.Validate( jwt ) );
		}
		
		[Test]
		public void Validate_InvalidDotNetSecurityTokenType_Failure() {
			Mock<SecurityToken> securityTokenMock = new Mock<SecurityToken>();
			string jwt = TestTokenProvider.MakeJwt(
				Constants.ALLOWED_SIGNATURE_ALGORITHM,
				Constants.ALLOWED_TOKEN_TYPE,
				"{}",
				TestTokenProvider.CreateRSAParams()
				);

			IJwtValidator validator = MakeValidator( securityTokenMock.Object );
			Assert.Throws<InvalidCastException>( () => validator.Validate( jwt ) );
		}

		[Test]
		public void Validate_Null_Failure() {
			Mock<SecurityToken> securityTokenMock = new Mock<SecurityToken>();

			IJwtValidator validator = MakeValidator( securityTokenMock.Object );
			Assert.Throws<ArgumentException>( () => validator.Validate( null ) );
		}

		private IJwtValidator MakeValidator( string jwt ) {
			JwtSecurityToken jwtToken = new JwtSecurityToken( jwt );
			return MakeValidator( jwtToken );
		}

		private IJwtValidator MakeValidator( SecurityToken token ) {
			Mock<IPublicKeyProvider> keyProviderMock = new Mock<IPublicKeyProvider>();
			Mock<IPublicKey> keyMock = new Mock<IPublicKey>();
			keyProviderMock.Setup( x => x.Get() ).Returns( keyMock.Object );
			Mock<ISecurityTokenValidator> tokenValidatorMock = new Mock<ISecurityTokenValidator>();
			ClaimsPrincipal principal = new ClaimsPrincipal();

			tokenValidatorMock.Setup( x => x.ValidateToken(
				It.IsAny<string>(),
				It.IsAny<TokenValidationParameters>(),
				out token
				) )
				.Returns( principal );

			IJwtValidator validator = new JwtValidator( keyProviderMock.Object, tokenValidatorMock.Object );
			return validator;
		}
	}
}
