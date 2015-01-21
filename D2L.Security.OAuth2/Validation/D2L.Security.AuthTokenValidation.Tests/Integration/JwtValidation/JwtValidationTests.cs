using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.PublicKeys.Default;
using D2L.Security.AuthTokenValidation.Tests.Utilities;
using D2L.Security.AuthTokenValidation.JwtValidation;
using D2L.Security.AuthTokenValidation.JwtValidation.Default;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Integration.JwtValidation {

	[TestFixture]
	internal sealed class JwtValidation {

		private const string SCOPE = TestCredentials.LOReSScopes.MANAGE;
		private const string VALID_ISSUER = "https://api.d2l.com/auth";
		private const string VALID_ALGORITHM = "RS256";
		private const string VALID_TOKEN_TYPE = "JWT";

		private RSACryptoServiceProvider m_cryptoServiceProvider;
		private RSAParameters m_rsaParameters;

		private IJwtValidator m_validator;

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
			DateTime expiry = DateTime.UtcNow + TimeSpan.FromMinutes( 15 );
			string payload = TestTokenProvider.MakePayload( VALID_ISSUER, SCOPE, expiry );
			string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, VALID_TOKEN_TYPE, payload, m_rsaParameters );

			IValidatedJwt validatedToken = m_validator.Validate( jwt );
			Assertions.ContainsScopeValue( validatedToken, SCOPE );

			// Unix time ignores milliseconds, so we have a tolerance of 999 milliseconds
			TimeSpan delta = expiry - validatedToken.Expiry;
			TimeSpan baseline = TimeSpan.FromMilliseconds( 999 );

			Assert.LessOrEqual( delta, baseline );
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
		public void TruncatedJwt_Failure() {
			string payload = TestTokenProvider.MakePayload( VALID_ISSUER, SCOPE, TimeSpan.FromMinutes( 15 ) );
			string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, VALID_TOKEN_TYPE, payload, m_rsaParameters );
			// remove beginning to malform
			jwt = jwt.Substring( 1 );

			Assertions.ExceptionStemsFrom<ArgumentException>(
				() => m_validator.Validate( jwt )
				);
		}

		[Test]
		public void EmptyHeader_Failure() {
			string payload = TestTokenProvider.MakePayload( VALID_ISSUER, SCOPE, TimeSpan.FromMinutes( 15 ) );
			string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, VALID_TOKEN_TYPE, payload, m_rsaParameters );
			int indexOfFirstDot = jwt.IndexOf( '.' );
			jwt = jwt.Substring( indexOfFirstDot );

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
		public void EmptySignature_Failure() {
			string payload = TestTokenProvider.MakePayload( VALID_ISSUER, SCOPE, TimeSpan.FromMinutes( 15 ) );
			string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, VALID_TOKEN_TYPE, payload, m_rsaParameters );
			int indexOfLastDot = jwt.LastIndexOf( '.' );
			jwt = jwt.Substring( 0, indexOfLastDot + 1 );

			Assertions.ExceptionStemsFrom<SecurityTokenValidationException>(
				() => m_validator.Validate( jwt )
				);
		}

		[Test]
		public void TooFewJwtSegments_Failure() {
			string payload = TestTokenProvider.MakePayload( VALID_ISSUER, SCOPE, TimeSpan.FromMinutes( 15 ) );
			string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, VALID_TOKEN_TYPE, payload, m_rsaParameters );
			int indexOfLastDot = jwt.LastIndexOf( '.' );
			jwt = jwt.Substring( 0, indexOfLastDot );

			Assertions.ExceptionStemsFrom<ArgumentException>(
				() => m_validator.Validate( jwt )
				);
		}

		[Test]
		public void TooManyJwtSegments_Failure() {
			string payload = TestTokenProvider.MakePayload( VALID_ISSUER, SCOPE, TimeSpan.FromMinutes( 15 ) );
			string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, VALID_TOKEN_TYPE, payload, m_rsaParameters );
			jwt += ".asdf";

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

			ISecurityTokenValidator tokenHandler = JwtHelper.CreateTokenHandler();

			m_validator = new JwtValidator(
				publicKeyProviderMock.Object,
				tokenHandler
				);
		}
	}
}
