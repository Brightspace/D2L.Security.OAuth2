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
			string jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSIsImtpZCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSJ9.eyJjbGllbnRfaWQiOiJsb3Jlc19tYW5hZ2VyX2NsaWVudCIsInNjb3BlIjoiaHR0cHM6Ly9hcGkuYnJpZ2h0c3BhY2UuY29tL2F1dGgvbG9yZXMubWFuYWdlIiwiaXNzIjoiaHR0cHM6Ly9hcGkuZDJsLmNvbS9hdXRoIiwiYXVkIjoiaHR0cHM6Ly9hcGkuZDJsLmNvbS9hdXRoL3Jlc291cmNlcyIsImV4cCI6MTQyMTI3MDExMiwibmJmIjoxNDIxMjY2NTEyfQ.mvx8lLbS_AxMEpFGW_KrZ7fTq1O0KbvHPVS5igDk8gDF_TdrlyuyRcpYGtdWqt4YVDg5reJDTvF_4tg9lHQB78mrKrib_d1bbqt2eRvqHA8Q5vo6y_1OyrOWnUByH0RC7fROCJBojpUF72oJGAl4DrwabVmK-oqU-7_jVGLJVAWEMixoiH3lsjGzLZvJadi3RSa7ZmDU37j6eWblo-VHT_f1kDD3ESKLRR6-oQjJrUK-CUNzHrNGLF60LvV1HW1DOQgdCrwPLKJHE0LobBm5skMNgxHYwIXTmFuQGeoebA35hNQYLySrw8F10K2V1xGZrIIc9HLHQYcfjAPfCM4Kmw";
			IJWTValidator validator = MakeValidator( jwt );
			Assert.DoesNotThrow( () => validator.Validate( jwt ) );
		}

		[Test]
		public void Validate_InvalidAlgorithm_Failure() {
			string jwt = TokenProvider.MakeJwt(
				"INVALIDALGORITHM",
				"JWT",
				"{}",
				TokenProvider.GetMeAKey()
				);
			IJWTValidator validator = MakeValidator( jwt );
			Assert.Throws<InvalidTokenTypeException>( () => validator.Validate( jwt ) );
		}

		[Ignore("To be translated into an integration test")]
		[Test]
		public void Validate_InvalidTokenType_Failure() {
			string jwt = TokenProvider.MakeJwt(
				"RS256",
				"INVALIDTYPE",
				"{}",
				TokenProvider.GetMeAKey()
				);
			Assert.Throws<ArgumentException>( () => new JwtSecurityToken( jwt ) );
		}

		[Test]
		public void Validate_InvalidDotNetSecurityTokenType_Failure() {
			Mock<SecurityToken> securityTokenMock = new Mock<SecurityToken>();
			string jwt = TokenProvider.MakeJwt(
				"RS256",
				"JWT",
				"{}",
				TokenProvider.GetMeAKey()
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
