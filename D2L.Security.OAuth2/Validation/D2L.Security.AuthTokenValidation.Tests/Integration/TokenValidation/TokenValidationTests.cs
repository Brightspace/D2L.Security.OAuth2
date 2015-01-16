using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.PublicKeys.Default;
using D2L.Security.AuthTokenValidation.Tests.Utilities;
using D2L.Security.AuthTokenValidation.TokenValidation;
using D2L.Security.AuthTokenValidation.TokenValidation.Default;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Integration.TokenValidation {

	[TestFixture]
	internal sealed class TokenValidationTests {

		private const string SCOPE = "https://api.brightspace.com/auth/lores.manage";
		private const string VALID_ISSUER = "https://api.d2l.com/auth";
		private const string VALID_ALGORITHM = "RS256";
		private const string VALID_TOKEN_TYPE = "JWT";

		private RSACryptoServiceProvider m_cryptoServiceProvider;
		private RSAParameters m_rsaParameters;

		private IJWTValidator m_validator;

		[SetUp]
		public void SetUp() {
			// generate new, random RSA parameters
			m_rsaParameters = TestTokenProvider.CreateRSAParams();
			// and a service which will provide keys based on them
			m_cryptoServiceProvider = new RSACryptoServiceProvider();
			m_cryptoServiceProvider.ImportParameters( m_rsaParameters );

			InitializeValidator();
		}

		[TearDown]
		public void TearDown() {
			m_cryptoServiceProvider.SafeDispose();
		}

		[Test]
		public void Valid_Success() {
			string payload = TestTokenProvider.MakePayload( VALID_ISSUER, SCOPE, TimeSpan.FromMinutes( 15 ) );
			string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, VALID_TOKEN_TYPE, payload, m_rsaParameters );

			IValidatedJWT validatedToken = m_validator.Validate( jwt );
			Assertions.ContainsScopeValue( validatedToken, SCOPE );
		}

		[Test]
		public void Expired_Failure() {
			string payload = TestTokenProvider.MakePayload( VALID_ISSUER, SCOPE, TimeSpan.FromMinutes( -15 ) );
			string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, VALID_TOKEN_TYPE, payload, m_rsaParameters );

			Assertions.ExceptionStemsFrom<SecurityTokenExpiredException>(
				() => m_validator.Validate( jwt )
				);
		}

		[Test]
		public void InvalidAlgorithm_Failure() {
			string payload = TestTokenProvider.MakePayload( VALID_ISSUER, SCOPE, TimeSpan.FromMinutes( 15 ) );
			string jwt = TestTokenProvider.MakeJwt( "invalidalgorithm", VALID_TOKEN_TYPE, payload, m_rsaParameters );

			Assertions.ExceptionStemsFrom<CryptographicException>( 
				() => m_validator.Validate( jwt ) 
				);
		}

		[Test]
		public void InvalidTokenType_Failure() {
			string payload = TestTokenProvider.MakePayload( VALID_ISSUER, SCOPE, TimeSpan.FromMinutes( 15 ) );
			string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, "invalidtokentype", payload, m_rsaParameters );

			Assertions.ExceptionStemsFrom<SecurityTokenException>(
				() => m_validator.Validate( jwt )
				);
		}

		[Test]
		public void InvalidIssuer_Failure() {
			string payload = TestTokenProvider.MakePayload( "invalidissuer", SCOPE, TimeSpan.FromMinutes( 15 ) );
			string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, VALID_TOKEN_TYPE, payload, m_rsaParameters );

			Assertions.ExceptionStemsFrom<SecurityTokenInvalidIssuerException>(
				() => m_validator.Validate( jwt )
				);
		}

		[Test]
		public void NullToken_Failure() {
			Assertions.ExceptionStemsFrom<ArgumentException>(
				() => m_validator.Validate( null )
				);
		}

		[Test]
		public void EmptyToken_Failure() {
			Assertions.ExceptionStemsFrom<ArgumentException>(
				() => m_validator.Validate( string.Empty )
				);
		}

		[TestCase( "." )]
		[TestCase( "..!!!!!...." )]
		public void NonBase64Token_Failure( string jwt ) {
			Assertions.ExceptionStemsFrom<ArgumentException>(
				() => m_validator.Validate( jwt )
				);
		}

		[Test]
		public void TruncatedJWT_Failure() {
			string payload = TestTokenProvider.MakePayload( VALID_ISSUER, SCOPE, TimeSpan.FromMinutes( 15 ) );
			string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, VALID_TOKEN_TYPE, payload, m_rsaParameters );
			// remove beginning to malform
			jwt = jwt.Substring( 1 );

			Assertions.ExceptionStemsFrom<ArgumentException>(
				() => m_validator.Validate( jwt )
				);
		}

		[Test]
		public void EmptyPayload_Failure() {
			string payload = string.Empty;
			string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, VALID_TOKEN_TYPE, payload, m_rsaParameters );

			Assertions.ExceptionStemsFrom<ArgumentException>(
				() => m_validator.Validate( jwt )
				);
		}

		[Test]
		public void MalformedJson_Failure() {
			string payload = TestTokenProvider.MakePayload( VALID_ISSUER, SCOPE, TimeSpan.FromMinutes( 15 ) );
			// remove beginning to malform
			payload = payload.Substring( 1 );
			string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, VALID_TOKEN_TYPE, payload, m_rsaParameters );

			Assertions.ExceptionStemsFrom<ArgumentException>(
				() => m_validator.Validate( jwt )
				);
		}

		private void InitializeValidator() {
			RsaKeyIdentifierClause clause = new RsaKeyIdentifierClause( m_cryptoServiceProvider );
			RsaSecurityToken securityToken = new RsaSecurityToken( m_cryptoServiceProvider );

			IPublicKey publicKey = new PublicKey( securityToken, VALID_ISSUER );
			Mock<IPublicKeyProvider> publicKeyProviderMock = new Mock<IPublicKeyProvider>();
			publicKeyProviderMock.Setup( x => x.Get() ).Returns( publicKey );

			ISecurityTokenValidator tokenHandler = JWTHelper.CreateTokenHandler();

			m_validator = new JWTValidator(
				publicKeyProviderMock.Object,
				tokenHandler
				);
		}
	}
}
