using System;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.Tests.Utilities;
using D2L.Security.AuthTokenValidation.TokenValidation;
using D2L.Security.AuthTokenValidation.TokenValidation.Default;
using D2L.Security.AuthTokenValidation.TokenValidation.Exceptions;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Unit.TokenValidation.Default {
	
	[TestFixture]
	internal sealed class JWTValidatorTests {

		[Test]
		public void Validate_Success() {
			string jwt = TestTokenProvider.MakeJwt(
				"RS256",
				"JWT",
				"{}",
				TestTokenProvider.CreateRSAParams()
				);
			IJWTValidator validator = MakeValidator( jwt );
			Assert.DoesNotThrow( () => validator.Validate( jwt ) );
		}

		[Test]
		public void Validate_InvalidAlgorithm_Failure() {
			string jwt = TestTokenProvider.MakeJwt(
				"INVALIDALGORITHM",
				"JWT",
				"{}",
				TestTokenProvider.CreateRSAParams()
				);
			IJWTValidator validator = MakeValidator( jwt );
			Assert.Throws<InvalidTokenTypeException>( () => validator.Validate( jwt ) );
		}
		
		[Test]
		public void Validate_InvalidDotNetSecurityTokenType_Failure() {
			Mock<SecurityToken> securityTokenMock = new Mock<SecurityToken>();
			string jwt = TestTokenProvider.MakeJwt(
				"RS256",
				"JWT",
				"{}",
				TestTokenProvider.CreateRSAParams()
				);

			IJWTValidator validator = MakeValidator( securityTokenMock.Object );
			Assert.Throws<InvalidCastException>( () => validator.Validate( jwt ) );
		}

		[Test]
		public void Validate_Null_Failure() {
			Mock<SecurityToken> securityTokenMock = new Mock<SecurityToken>();

			IJWTValidator validator = MakeValidator( securityTokenMock.Object );
			Assert.Throws<ArgumentException>( () => validator.Validate( null ) );
		}

		private IJWTValidator MakeValidator( string jwt ) {
			JwtSecurityToken jwtToken = new JwtSecurityToken( jwt );
			return MakeValidator( jwtToken );
		}

		private IJWTValidator MakeValidator( SecurityToken token ) {
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

			IJWTValidator validator = new JWTValidator( keyProviderMock.Object, tokenValidatorMock.Object );
			return validator;
		}
	}
}
